"""Recoverable publication of bounded sets of staged binary files.

Publication is durable as a set, but visibility is intentionally sequential:
readers can observe a mixture while the individual atomic replacements run.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
import os
import shutil
import tempfile
import time
import uuid
from typing import Callable, Mapping, Optional

from core import outcomes, recovery_contracts, store
import file_ops
import path_safety
import publication_recovery


PUBLISH_PLAN_SCHEMA = "agw-publish-plan/v1"
MAX_PUBLISH_OPERATIONS = 64
ATOMICITY = "recoverable-set"
VISIBILITY = "per-file-sequential"


CandidateValidator = Callable[[str, Mapping], object]
ClaimValidator = Callable[[Mapping, Mapping, Mapping, str], object]
RUN_PLAN_SCHEMA = "agw-run-plan/v1"
_PARENT_KEYS = {"schema", "plan_id", "plan_sha256", "claim_id"}
_RUN_PLAN_KEYS = {
    "schema", "mode", "freshness", "cwd", "command", "artifacts",
    "observed_roots", "execution", "plan_sha256",
}
_FRESHNESS_KEYS = {"plan_id", "issued_at_utc", "expires_at_utc", "max_uses"}
_PARENT_ARTIFACT_KEYS = {
    "number", "staged", "staged_before", "target", "target_before", "validation",
}
_VALIDATION_KEYS = {
    "kind", "tier", "preserve_against", "preserve_against_sha256",
}


def _absolute_literal(value: object, label: str, *, must_exist: bool = False) -> str:
    raw = str(value or "").strip()
    if not raw or "\x00" in raw or any(char in raw for char in "*?["):
        raise file_ops.FileOperationError(f"{label} must be a literal path")
    path = os.path.abspath(os.path.expanduser(raw))
    if must_exist and (not os.path.isfile(path) or os.path.islink(path)):
        raise file_ops.FileOperationError(f"{label} is not an ordinary file")
    return path


def _hash_label(value: object, label: str, *, allow_absent: bool = False) -> str:
    digest = str(value or "").strip().lower()
    if allow_absent and digest == "absent":
        return digest
    if not file_ops._HASH_RE.fullmatch(digest):
        suffix = " or 'absent'" if allow_absent else ""
        raise file_ops.FileOperationError(f"{label} must be a SHA-256{suffix}")
    return digest


def _path_keys(path: str) -> tuple[str, str]:
    identity = path_safety.identify(path)
    return identity.native_key, identity.unicode_key


def _require_distinct_paths(operations: list[dict]) -> None:
    native: dict[str, tuple[str, str]] = {}
    unicode: dict[str, tuple[str, str]] = {}
    filesystem: dict[tuple[int, int], tuple[str, str]] = {}
    for item in operations:
        for role in ("stage", "target"):
            path = item[role]
            native_key, unicode_key = _path_keys(path)
            previous = native.get(native_key)
            if previous:
                raise file_ops.FileOperationError(
                    "publish plan paths must identify distinct files",
                    {"paths": [previous[1], path], "roles": [previous[0], role]},
                )
            previous = unicode.get(unicode_key)
            if previous:
                raise file_ops.FileOperationError(
                    "publish plan paths collide after Unicode normalization",
                    {"paths": [previous[1], path], "roles": [previous[0], role],
                     "normalization": "NFC"},
                )
            native[native_key] = (role, path)
            unicode[unicode_key] = (role, path)
            if os.path.lexists(path):
                stat_result = os.stat(path, follow_symlinks=False)
                file_key = (
                    int(getattr(stat_result, "st_dev", 0)),
                    int(getattr(stat_result, "st_ino", 0)),
                )
                previous = filesystem.get(file_key)
                if previous and file_key != (0, 0):
                    raise file_ops.FileOperationError(
                        "publish plan paths identify the same existing file",
                        {"paths": [previous[1], path],
                         "roles": [previous[0], role]},
                    )
                filesystem[file_key] = (role, path)


def build_publish_plan(
    operations: list[dict], *, cwd: str = "", parent: Optional[Mapping] = None,
) -> dict:
    """Bind exact staged and target states into a canonical publication plan."""
    if not isinstance(operations, list) or not 1 <= len(operations) <= MAX_PUBLISH_OPERATIONS:
        raise file_ops.FileOperationError(
            f"publish plan requires 1 to {MAX_PUBLISH_OPERATIONS} operations"
        )
    working = os.path.abspath(os.path.expanduser(cwd or os.getcwd()))
    if not os.path.isdir(working):
        raise file_ops.FileOperationError("publish plan working directory does not exist")
    planned = []
    for number, supplied in enumerate(operations, 1):
        if not isinstance(supplied, dict):
            raise file_ops.FileOperationError("each publish operation must be an object")
        def located(name: str, source_name: str = "") -> str:
            raw = str(supplied.get(source_name or name) or "")
            expanded = os.path.expanduser(raw)
            return _absolute_literal(
                expanded if os.path.isabs(expanded) else os.path.join(working, expanded),
                name, must_exist=name == "stage",
            )
        stage_key = "staged" if "staged" in supplied else "stage"
        stage = located("stage", stage_key)
        target = file_ops.resolve_target(located("target"))
        stage_hash = store.file_sha256(stage)
        supplied_stage_hash = str(
            supplied.get("expected_stage_hash") or supplied.get("stage_hash")
            or supplied.get("staged_sha256") or ""
        ).strip().lower()
        if supplied_stage_hash:
            supplied_stage_hash = _hash_label(supplied_stage_hash, "expected staged hash")
            if supplied_stage_hash != stage_hash:
                raise file_ops.PreimageHashConflict(
                    "CONFLICT: staged file hash does not match expected version",
                    {"path": stage, "expected": supplied_stage_hash, "actual": stage_hash},
                )
        expected = str(
            supplied.get("expected_hash") or supplied.get("target_before") or ""
        ).strip().lower()
        before = file_ops._check_expected(target, expected)
        raw_validation = supplied.get("validation", "raw")
        validation = str(
            raw_validation.get("kind") if isinstance(raw_validation, Mapping)
            else raw_validation
        ).strip().lower()
        if validation not in {"raw", "office"}:
            raise file_ops.FileOperationError("validation must be 'raw' or 'office'")
        planned.append({
            "number": number,
            "staged": stage,
            "target": target,
            "staged_sha256": stage_hash,
            "target_before": before or "absent",
            "validation": dict(raw_validation) if isinstance(
                raw_validation, Mapping
            ) else validation,
        })
    _require_distinct_paths([{
        **item, "stage": item["staged"],
    } for item in planned])
    result = {
        "schema": PUBLISH_PLAN_SCHEMA,
        "cwd": working,
        "operations": planned,
    }
    if parent is not None:
        result["parent"] = dict(parent)
    return recovery_contracts.bind_plan_hash(result)


# Descriptive compatibility alias for early integrators.
build_staged_publish_plan = build_publish_plan


def validate_publish_plan(plan: Mapping, *, expected_plan_hash: str = "") -> dict:
    """Return a normalized plan after strict schema and self-hash validation."""
    if not isinstance(plan, Mapping) or plan.get("schema") != PUBLISH_PLAN_SCHEMA:
        raise file_ops.FileOperationError("unsupported or missing publish-plan schema")
    allowed_top = {"schema", "cwd", "operations", "plan_sha256", "parent"}
    if set(plan) not in (
        allowed_top - {"parent"}, allowed_top,
    ):
        raise file_ops.FileOperationError("publish plan top-level fields are invalid")
    if not recovery_contracts.plan_hash_valid(plan):
        raise file_ops.FileOperationError("publish plan self-hash is missing or invalid")
    actual_hash = str(plan.get("plan_sha256") or "")
    if expected_plan_hash:
        wanted = _hash_label(expected_plan_hash, "expected plan hash")
        if wanted != actual_hash:
            raise file_ops.PreimageHashConflict(
                "CONFLICT: publish plan does not match expected version",
                {"expected": wanted, "actual": actual_hash},
            )
    supplied = plan.get("operations")
    if not isinstance(supplied, list) or not 1 <= len(supplied) <= MAX_PUBLISH_OPERATIONS:
        raise file_ops.FileOperationError(
            f"publish plan requires 1 to {MAX_PUBLISH_OPERATIONS} operations"
        )
    normalized = []
    for number, item in enumerate(supplied, 1):
        if not isinstance(item, Mapping) or item.get("number") != number:
            raise file_ops.FileOperationError("publish plan operation numbering is invalid")
        allowed_keys = {
            "number", "staged", "target", "staged_sha256", "target_before",
            "validation",
        }
        if set(item) != allowed_keys:
            raise file_ops.FileOperationError("publish plan operation fields are invalid")
        stage = _absolute_literal(item.get("staged"), "staged")
        target = _absolute_literal(item.get("target"), "target")
        if stage != item.get("staged") or target != item.get("target"):
            raise file_ops.FileOperationError("publish plan paths must be normalized absolute paths")
        if not os.path.isdir(os.path.dirname(target)):
            raise file_ops.FileOperationError("target parent directory does not exist")
        raw_validation = item.get("validation")
        if isinstance(raw_validation, Mapping):
            if set(raw_validation) != _VALIDATION_KEYS:
                raise file_ops.FileOperationError("publish plan validation fields are invalid")
            validation = dict(raw_validation)
            validation_mode = str(validation.get("kind") or "")
        else:
            validation = str(raw_validation or "")
            validation_mode = validation
        if validation_mode not in {"raw", "office"}:
            raise file_ops.FileOperationError("publish plan has an invalid validation mode")
        normalized.append({
            "number": number,
            "stage": stage,
            "target": target,
            "stage_hash": _hash_label(item.get("staged_sha256"), "staged hash"),
            "target_before": _hash_label(
                item.get("target_before"), "target-before hash", allow_absent=True,
            ),
            "validation": validation,
            "validation_mode": validation_mode,
        })
    _require_distinct_paths(normalized)
    cwd = _absolute_literal(plan.get("cwd"), "publish plan cwd")
    if cwd != plan.get("cwd") or not os.path.isdir(cwd):
        raise file_ops.FileOperationError(
            "publish plan cwd must be an existing normalized absolute directory"
        )
    normalized_plan = {
        "schema": PUBLISH_PLAN_SCHEMA,
        "cwd": cwd,
        "operations": normalized,
        "plan_sha256": actual_hash,
    }
    if "parent" in plan:
        parent = plan["parent"]
        if not isinstance(parent, Mapping) or set(parent) != _PARENT_KEYS:
            raise file_ops.PublishParentBindingInvalid(
                "publish plan parent binding is invalid"
            )
        if parent.get("schema") != RUN_PLAN_SCHEMA \
                or not str(parent.get("plan_id") or "") \
                or not str(parent.get("claim_id") or ""):
            _parent_invalid("publish plan parent identity is invalid")
        if not file_ops._HASH_RE.fullmatch(str(parent.get("plan_sha256") or "")):
            _parent_invalid("publish plan parent hash is invalid")
        normalized_plan["parent"] = dict(parent)
    return normalized_plan


def _parent_invalid(message: str, details: Optional[dict] = None):
    raise file_ops.PublishParentBindingInvalid(message, details)


def _exact_mapping(value: object, keys: set[str], label: str) -> Mapping:
    if not isinstance(value, Mapping) or set(value) != keys:
        _parent_invalid(f"{label} fields are invalid")
    return value


def _validate_parent_plan(parent_plan: Mapping, child: Mapping) -> dict:
    """Validate the frozen run-plan fields needed for publication authority."""
    parent_plan = _exact_mapping(parent_plan, _RUN_PLAN_KEYS, "parent run plan")
    if parent_plan.get("schema") != RUN_PLAN_SCHEMA \
            or not recovery_contracts.plan_hash_valid(parent_plan):
        _parent_invalid("parent run plan schema or canonical hash is invalid")
    binding = child.get("parent")
    if not isinstance(binding, Mapping):
        _parent_invalid("parent-bound publication requires a child parent binding")
    freshness = _exact_mapping(
        parent_plan.get("freshness"), _FRESHNESS_KEYS, "parent freshness",
    )
    plan_id = str(freshness.get("plan_id") or "")
    if not plan_id or binding.get("schema") != RUN_PLAN_SCHEMA \
            or binding.get("plan_id") != plan_id \
            or binding.get("plan_sha256") != parent_plan.get("plan_sha256"):
        _parent_invalid("child binding does not identify the supplied parent plan")
    issued = freshness.get("issued_at_utc")
    expires = freshness.get("expires_at_utc")
    if isinstance(issued, bool) or not isinstance(issued, (int, float)) \
            or isinstance(expires, bool) or not isinstance(expires, (int, float)):
        _parent_invalid("parent freshness timestamps must be epoch seconds")
    now = time.time()
    if issued > now + 300 or expires < now or expires < issued \
            or expires - issued > 86400 or freshness.get("max_uses") != 1:
        _parent_invalid("parent run plan is stale or has invalid freshness bounds")
    artifacts = parent_plan.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != len(child["operations"]):
        _parent_invalid("parent artifacts do not match child operation count")
    parent_paths = []
    for number, (artifact, operation) in enumerate(
            zip(artifacts, child["operations"]), 1):
        artifact = _exact_mapping(
            artifact, _PARENT_ARTIFACT_KEYS, "parent artifact",
        )
        validation = _exact_mapping(
            artifact.get("validation"), _VALIDATION_KEYS, "parent validation",
        )
        if artifact.get("number") != number:
            _parent_invalid("parent artifact numbering is invalid")
        staged = _absolute_literal(artifact.get("staged"), "parent staged")
        target = _absolute_literal(artifact.get("target"), "parent target")
        if staged != artifact.get("staged") or target != artifact.get("target"):
            _parent_invalid("parent artifact paths must be normalized absolute paths")
        _hash_label(artifact.get("staged_before"), "parent staged-before", allow_absent=True)
        _hash_label(artifact.get("target_before"), "parent target-before", allow_absent=True)
        preserve = validation.get("preserve_against")
        preserve_hash = str(validation.get("preserve_against_sha256") or "")
        if preserve:
            normalized_preserve = _absolute_literal(preserve, "preserve-against")
            if normalized_preserve != preserve:
                _parent_invalid("preserve-against path must be normalized and absolute")
            _hash_label(preserve_hash, "preserve-against hash")
        elif preserve_hash:
            _parent_invalid("preserve-against hash requires a preserve-against path")
        projection = {
            "number": artifact["number"], "staged": staged, "target": target,
            "target_before": artifact["target_before"],
            "validation": dict(validation),
        }
        child_projection = {
            "number": operation["number"], "staged": operation["stage"],
            "target": operation["target"],
            "target_before": operation["target_before"],
            "validation": operation["validation"],
        }
        if projection != child_projection:
            _parent_invalid(
                "parent artifacts are not the exact ordered child projection",
                {"operation": number},
            )
        parent_paths.extend((staged, target))
    try:
        path_safety.require_unique(parent_paths, label="parent artifact paths")
    except path_safety.PathSafetyError as exc:
        _parent_invalid(str(exc), exc.details)
    return dict(parent_plan)


def _validate_claim_mapping(parent: Mapping, claim: Mapping) -> dict:
    if not isinstance(claim, Mapping):
        _parent_invalid("parent-bound publication requires a durable claim mapping")
    required = {"claim_id", "plan_id", "plan_sha256", "state"}
    if not required.issubset(claim):
        _parent_invalid("parent claim is missing required identity fields")
    if claim.get("claim_id") != parent.get("claim_id") \
            or claim.get("plan_id") != parent.get("plan_id") \
            or claim.get("plan_sha256") != parent.get("plan_sha256") \
            or claim.get("state") != "CLAIMED":
        _parent_invalid("parent claim identity or state is invalid")
    if any(
        str(key).lower().startswith(("terminal", "publication", "published"))
        for key in claim
    ):
        _parent_invalid("parent claim is terminal or already published")
    return dict(claim)


def _validate_local_replay(parent: Mapping) -> None:
    for record in store.oplog_read():
        if record.get("claim_id") == parent.get("claim_id") \
                or (record.get("parent_plan_id") == parent.get("plan_id")
                    and record.get("parent_plan_sha256") == parent.get("plan_sha256")):
            _parent_invalid("parent claim or plan was already used for publication")


def _authoritative_parent_binding(
    child: Mapping, child_source: Mapping, parent_plan: Optional[Mapping],
    parent_claim: Optional[Mapping], claim_validator: Optional[ClaimValidator], phase: str,
) -> Optional[dict]:
    binding = child.get("parent")
    supplied = any(value is not None for value in (
        parent_plan, parent_claim, claim_validator,
    ))
    if binding is None:
        if supplied:
            _parent_invalid("standalone publication requires all parent inputs absent")
        return None
    if parent_plan is None or parent_claim is None or claim_validator is None:
        _parent_invalid(
            "parent-bound publication requires parent plan, claim, and claim validator"
        )
    try:
        parent = _validate_parent_plan(parent_plan, child)
        claim = _validate_claim_mapping(binding, parent_claim)
        _validate_local_replay(binding)
    except file_ops.PublishParentBindingInvalid:
        raise
    except Exception as exc:
        _parent_invalid(
            "parent publication binding validation failed",
            {"phase": phase, "cause": str(exc)},
        )
    try:
        verdict = claim_validator(parent, claim, child_source, phase)
    except file_ops.PublishParentBindingInvalid:
        raise
    except Exception as exc:
        _parent_invalid(
            "authoritative parent claim validation failed",
            {"phase": phase, "cause": str(exc)},
        )
    if verdict is not True:
        _parent_invalid(
            "authoritative parent claim validation refused publication",
            {"phase": phase},
        )
    return {
        "parent_plan_id": binding["plan_id"],
        "parent_plan_sha256": binding["plan_sha256"],
        "claim_id": binding["claim_id"],
    }


def _lock_name(path: str) -> tuple[str, str]:
    identity = path_safety.identify(path).native_key
    digest = hashlib.sha256(identity.encode("utf-8", "replace")).hexdigest()[:32]
    return identity, "file-" + digest


def _current_label(path: str) -> str:
    value = file_ops._current_hash(path)
    return value or "absent"


def _ordinary_file_identity(path: str) -> list[int]:
    if not os.path.isfile(path) or os.path.islink(path):
        raise file_ops.FileOperationError("candidate is not an ordinary file")
    info = os.stat(path, follow_symlinks=False)
    return [
        int(getattr(info, "st_dev", 0)), int(getattr(info, "st_ino", 0)),
        int(info.st_size), int(info.st_mtime_ns),
    ]


def _check_operation_preconditions(item: Mapping) -> None:
    if not os.path.isfile(item["stage"]) or os.path.islink(item["stage"]):
        raise file_ops.PreimageHashConflict(
            "CONFLICT: staged file is no longer an ordinary file",
            {"path": item["stage"], "expected": item["stage_hash"], "actual": "missing"},
        )
    actual_stage = store.file_sha256(item["stage"])
    if actual_stage != item["stage_hash"]:
        raise file_ops.PreimageHashConflict(
            "CONFLICT: staged file hash does not match publish plan",
            {"path": item["stage"], "expected": item["stage_hash"],
             "actual": actual_stage},
        )
    file_ops._check_expected(item["target"], item["target_before"])
    validation = item.get("validation")
    if isinstance(validation, Mapping) and validation.get("preserve_against"):
        file_ops._check_expected(
            validation["preserve_against"],
            validation["preserve_against_sha256"],
        )


def _fsync_file_and_parent(path: str) -> None:
    # Windows rejects FlushFileBuffers on a read-only CRT descriptor.
    with open(path, "r+b") as handle:
        os.fsync(handle.fileno())
    flags = getattr(os, "O_DIRECTORY", 0) | os.O_RDONLY
    try:
        descriptor = os.open(os.path.dirname(path), flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _validate_candidate(
    candidate: str, item: Mapping, validator: Optional[CandidateValidator]
) -> object:
    candidate_hash = store.file_sha256(candidate)
    if candidate_hash != item["stage_hash"]:
        raise file_ops.FileOperationError("same-directory candidate failed hash verification")
    validation = item.get("validation")
    mode = item.get("validation_mode", validation)
    if mode == "office" and validator is None:
        raise file_ops.FileOperationError(
            "Office publication requires a candidate validator",
            {"path": item["target"], "candidate": candidate},
        )
    if validator is None:
        return {"mode": "raw", "valid": True, "candidate_sha256": candidate_hash}
    report = validator(candidate, dict(item))
    if report is False or (isinstance(report, Mapping) and report.get("valid") is False):
        raise file_ops.FileOperationError(
            "staged publication candidate failed validation",
            {"path": item["target"], "candidate": candidate, "report": report},
        )
    report = report if report is not None else {"valid": True}
    try:
        json.dumps(report, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise file_ops.FileOperationError(
            "candidate validator report must be JSON-serializable",
            {"path": item["target"]},
        ) from exc
    if mode != "office":
        return report
    required = {
        "valid", "candidate_sha256", "tier", "package_validation",
        "baseline_path", "baseline_expected_sha256", "baseline_actual_sha256",
        "preservation_validation",
    }
    if not isinstance(report, Mapping) or set(report) != required:
        raise file_ops.FileOperationError("Office validator receipt fields are invalid")
    tier = str(validation.get("tier") or "") if isinstance(validation, Mapping) else ""
    baseline = str(validation.get("preserve_against") or "") \
        if isinstance(validation, Mapping) else ""
    expected_baseline = str(validation.get("preserve_against_sha256") or "") \
        if isinstance(validation, Mapping) else ""
    requires_preservation = bool(baseline) or item["target"].lower().endswith(".xlsm")
    if not tier or report.get("tier") != tier \
            or report.get("candidate_sha256") != candidate_hash \
            or report.get("package_validation") is not True:
        raise file_ops.FileOperationError("Office validator receipt is not authenticated")
    if item["target"].lower().endswith(".xlsm") and (not baseline or not expected_baseline):
        raise file_ops.FileOperationError(
            "macro-enabled Office publication requires an exact preservation baseline"
        )
    if requires_preservation:
        actual_baseline = file_ops._current_hash(baseline) if baseline else None
        if not baseline or report.get("baseline_path") != baseline \
                or report.get("baseline_expected_sha256") != expected_baseline \
                or report.get("baseline_actual_sha256") != actual_baseline \
                or actual_baseline != expected_baseline \
                or report.get("preservation_validation") is not True:
            raise file_ops.FileOperationError(
                "Office preservation validator receipt is not authenticated"
            )
    elif report.get("baseline_path") or report.get("baseline_expected_sha256") \
            or report.get("baseline_actual_sha256") \
            or report.get("preservation_validation") not in (False, None):
        raise file_ops.FileOperationError("Office validator receipt has an unexpected baseline")
    return dict(report)


def _make_candidates(
    operations: list[dict], validator: Optional[CandidateValidator]
) -> dict[int, str]:
    candidates = {}
    try:
        for item in operations:
            suffix = os.path.splitext(item["target"])[1]
            descriptor, candidate = tempfile.mkstemp(
                prefix=".agw-publish-", suffix=suffix,
                dir=os.path.dirname(item["target"]),
            )
            os.close(descriptor)
            candidates[item["number"]] = candidate
            shutil.copy2(item["stage"], candidate)
            _fsync_file_and_parent(candidate)
            item["validation_report"] = _validate_candidate(candidate, item, validator)
        return candidates
    except Exception:
        _cleanup_candidates(candidates.values())
        raise


def _cleanup_candidates(paths) -> None:
    for path in paths:
        if path and os.path.exists(path):
            try:
                os.unlink(path)
            except OSError:
                pass


def _terminal_record(
    prepared_id: str, state: str, operations: list[dict], *, error: str = "",
    rollback_errors: Optional[list[dict]] = None, recovered: bool = False,
    binding: Optional[Mapping] = None, plan_sha256: str = "",
    transaction_id: str = "",
) -> dict:
    publication = {
        "COMMITTED": outcomes.PublicationOutcome.COMMITTED.value,
        "ROLLED_BACK": outcomes.PublicationOutcome.ROLLED_BACK.value,
        "NEEDS_ATTENTION": outcomes.PublicationOutcome.NEEDS_ATTENTION.value,
    }[state]
    operation = outcomes.CompositeOutcome.SUCCESS.value \
        if state == "COMMITTED" or (recovered and state == "ROLLED_BACK") \
        else outcomes.CompositeOutcome.PROCESS_FAILED.value
    record = outcomes.completed_record({
        "op": "file-transaction-state",
        "transaction_id": transaction_id or uuid.uuid4().hex,
        "prepared_transaction_id": prepared_id,
        "state": state,
        "operations": operations,
        "atomicity": ATOMICITY,
        "visibility": VISIBILITY,
        "process_outcome": outcomes.ProcessOutcome.NOT_APPLICABLE.value,
        "contract_outcome": outcomes.ContractOutcome.NOT_EVALUATED.value,
        "publication_outcome": publication,
        "operation_outcome": operation,
        "recovered": recovered,
        "plan_sha256": plan_sha256,
        **dict(binding or {}),
    }, operation_outcome=operation)
    if error:
        record["error"] = error
    if rollback_errors is not None:
        record["rollback_errors"] = rollback_errors
        record["rolled_back"] = state == "ROLLED_BACK"
    appended, issues = store.oplog_append(record)
    if issues:
        raise file_ops.FileTransactionError(
            "publication terminal oplog contains malformed evidence"
        )
    if appended:
        return record
    _prepared, existing = _prepared_transaction(prepared_id)
    if existing is None or any(
        existing.get(key) != value for key, value in record.items()
    ):
        raise file_ops.FileTransactionError(
            "publication terminal identifier collision is not an exact duplicate"
        )
    return existing


def _result(
    prepared_id: str, plan: Mapping, operations: list[dict], state: str,
    binding: Optional[Mapping] = None,
) -> dict:
    publication = {
        "COMMITTED": outcomes.PublicationOutcome.COMMITTED.value,
        "ROLLED_BACK": outcomes.PublicationOutcome.ROLLED_BACK.value,
        "NEEDS_ATTENTION": outcomes.PublicationOutcome.NEEDS_ATTENTION.value,
    }[state]
    operation = outcomes.CompositeOutcome.SUCCESS.value \
        if state == "COMMITTED" else outcomes.CompositeOutcome.PROCESS_FAILED.value
    return {
        "operation": "publish-batch",
        "transaction_id": prepared_id,
        "plan_sha256": plan["plan_sha256"],
        "state": state,
        "recovery_state": state,
        "changed": sum(bool(item.get("changed")) for item in operations),
        "operations": operations,
        "atomicity": ATOMICITY,
        "visibility": VISIBILITY,
        "process_outcome": outcomes.ProcessOutcome.NOT_APPLICABLE.value,
        "publication_outcome": publication,
        "operation_outcome": operation,
        "outcome": operation,
        "outcome_known": True,
        **dict(binding or {}),
    }


def publish_staged_batch(
    plan: Mapping,
    *,
    expected_plan_hash: str = "",
    candidate_validator: Optional[CandidateValidator] = None,
    parent_plan: Optional[Mapping] = None,
    parent_claim: Optional[Mapping] = None,
    claim_validator: Optional[ClaimValidator] = None,
    dry_run: bool = False,
    retry_seconds: float = 5.0,
) -> dict:
    """Publish a hash-bound staged set with fail-closed PREPARED recovery."""
    if not dry_run and not expected_plan_hash:
        raise file_ops.FileOperationError("publication requires --expected-plan-hash")
    validated = validate_publish_plan(plan, expected_plan_hash=expected_plan_hash)
    binding = _authoritative_parent_binding(
        validated, plan, parent_plan, parent_claim, claim_validator, "pre_lock",
    )
    for item in validated["operations"]:
        _check_operation_preconditions(item)
    operations = validated["operations"]
    lock_paths = {item[key] for item in operations for key in ("stage", "target")}
    lock_paths.update(
        item["validation"]["preserve_against"]
        for item in operations
        if isinstance(item.get("validation"), Mapping)
        and item["validation"].get("preserve_against")
    )
    with ExitStack() as held_locks:
        for _, name in sorted(_lock_name(path) for path in lock_paths):
            held_locks.enter_context(store.Lock(name, timeout=10.0))
        binding = _authoritative_parent_binding(
            validated, plan, parent_plan, parent_claim, claim_validator, "under_lock",
        )
        for item in operations:
            _check_operation_preconditions(item)
            item["changed"] = item["target_before"] != item["stage_hash"]
        candidates = _make_candidates(operations, candidate_validator)
        if dry_run:
            _cleanup_candidates(candidates.values())
            result_operations = [{
                "number": item["number"], "path": item["target"],
                "stage": item["stage"], "before_hash": item["target_before"],
                "after_hash": item["stage_hash"], "changed": int(item["changed"]),
                "validation": item["validation"],
                "validation_report": item.get("validation_report"),
            } for item in operations]
            return {
                "operation": "publish-batch", "dry_run": True,
                "plan_sha256": validated["plan_sha256"],
                "changed": sum(item["changed"] for item in operations),
                "operations": result_operations,
                "atomicity": ATOMICITY, "visibility": VISIBILITY,
                "process_outcome": outcomes.ProcessOutcome.NOT_APPLICABLE.value,
                "publication_outcome": outcomes.PublicationOutcome.VALIDATED.value,
                "operation_outcome": outcomes.CompositeOutcome.SUCCESS.value,
                "outcome": outcomes.CompositeOutcome.SUCCESS.value,
                "outcome_known": True,
                **dict(binding or {}),
            }
        changed = [item for item in operations if item["changed"]]
        if not changed and binding is None:
            _cleanup_candidates(candidates.values())
            return _result("", validated, [], "COMMITTED")

        try:
            receipts = file_ops._snapshots(
                [item["target"] for item in changed], "publish-batch"
            ) if changed else []
        except Exception:
            _cleanup_candidates(candidates.values())
            raise
        receipt_by_number = dict(zip((item["number"] for item in changed), receipts))
        prepared_id = uuid.uuid4().hex
        recorded_operations = []
        for item in operations:
            receipt = receipt_by_number.get(item["number"])
            recorded = {
                "number": item["number"], "path": item["target"],
                "stage": item["stage"], "candidate": candidates[item["number"]],
                "candidate_identity": _ordinary_file_identity(
                    candidates[item["number"]]
                ),
                "before_hash": item["target_before"],
                "after_hash": item["stage_hash"], "changed": int(item["changed"]),
                "validation": item["validation"],
                "validation_report": item.get("validation_report"),
            }
            if receipt is not None:
                recorded.update({
                    "snapshot_transaction_id": receipt.transaction_id,
                    "snapshot_state": receipt.state,
                    "recovery": receipt.to_dict(prepared_id),
                })
            recorded_operations.append(recorded)
        prepared = {
            "op": "file-transaction-prepared",
            "transaction_id": prepared_id,
            "state": "PREPARED",
            "plan_sha256": validated["plan_sha256"],
            "operations": recorded_operations,
            "atomicity": ATOMICITY,
            "visibility": VISIBILITY,
            **dict(binding or {}),
        }
        store.oplog_append(prepared)

        published = []
        try:
            for item in operations:
                _check_operation_preconditions(item)
            for item, recorded in zip(operations, recorded_operations):
                if not item["changed"]:
                    continue
                candidate = candidates[item["number"]]
                recorded["publish_attempts"] = file_ops.replace_with_retry(
                    candidate, item["target"], retry_seconds,
                )
                candidates[item["number"]] = ""
                published.append((item, receipt_by_number[item["number"]], recorded))
                if _current_label(item["target"]) != item["stage_hash"]:
                    raise file_ops.FileOperationError(
                        "published transaction file failed final hash verification"
                    )
        except Exception as exc:
            rollback_errors = []
            for item, receipt, recorded in reversed(published):
                try:
                    file_ops._restore_published(
                        receipt,
                        None if item["target_before"] == "absent" else item["target_before"],
                        item["target"],
                    )
                    if _current_label(item["target"]) != item["target_before"]:
                        raise OSError("restored target failed verification")
                except Exception as rollback_exc:
                    rollback_errors.append({
                        "path": item["target"], "error": str(rollback_exc),
                        "snapshot_transaction_id": receipt.transaction_id,
                    })
            state = "NEEDS_ATTENTION" if rollback_errors else "ROLLED_BACK"
            _terminal_record(
                prepared_id, state, recorded_operations, error=str(exc),
                rollback_errors=rollback_errors,
                binding=binding,
                plan_sha256=validated["plan_sha256"],
            )
            _cleanup_candidates(candidates.values())
            raise file_ops.FileTransactionError(
                "staged publication failed; " + (
                    "recovery is required for one or more targets"
                    if rollback_errors else "all published changes were rolled back"
                ),
                {"transaction_id": prepared_id, "state": state,
                 "cause": str(exc), "rolled_back": not rollback_errors,
                 "rollback_errors": rollback_errors},
            ) from exc

        terminal = _terminal_record(
            prepared_id, "COMMITTED", recorded_operations, binding=binding,
            plan_sha256=validated["plan_sha256"],
        )
        _cleanup_candidates(candidates.values())
        for recorded in recorded_operations:
            recorded.pop("candidate", None)
        result = _result(
            prepared_id, validated, recorded_operations, "COMMITTED", binding,
        )
        for key in (
            "process_outcome", "contract_outcome", "precondition_outcome",
            "policy_outcome", "environment_outcome", "publication_outcome",
            "operation_outcome", "outcome",
            "outcome_known", "outcome_source",
        ):
            result[key] = terminal[key]
        return result


def _prepared_transaction(transaction_id: str) -> tuple[dict, Optional[dict]]:
    prepared_records = []
    terminal_records = []
    for record in store.oplog_read():
        if record.get("op") == "file-transaction-prepared" \
                and record.get("transaction_id") == transaction_id:
            prepared_records.append(record)
        elif record.get("op") == "file-transaction-state" \
                and record.get("prepared_transaction_id") == transaction_id:
            terminal_records.append(record)
    if not prepared_records:
        raise LookupError(f"no staged publication transaction found: {transaction_id}")
    prepared_hashes = {
        recovery_contracts.canonical_sha256(record) for record in prepared_records
    }
    if len(prepared_hashes) != 1:
        raise file_ops.FileTransactionError(
            "prepared publication evidence is conflicting or ambiguous"
        )
    prepared = prepared_records[0]
    if terminal_records:
        terminal_hashes = {
            recovery_contracts.canonical_sha256(record) for record in terminal_records
        }
        terminal_states = {str(record.get("state") or "") for record in terminal_records}
        if len(terminal_hashes) != 1 or len(terminal_states) != 1 \
                or not all(recovery_contracts.publication_terminal_valid(prepared, record)
                           for record in terminal_records):
            raise file_ops.FileTransactionError(
                "publication terminal evidence is conflicting or invalid"
            )
        return prepared, terminal_records[0]
    return prepared, None


def _prepared_binding(prepared: Mapping) -> dict:
    fields = ("parent_plan_id", "parent_plan_sha256", "claim_id")
    present = [key for key in fields if key in prepared]
    if present and (len(present) != len(fields)
                    or not all(str(prepared.get(key) or "") for key in fields)
                    or not file_ops._HASH_RE.fullmatch(
                        str(prepared.get("parent_plan_sha256") or ""))):
        raise file_ops.FileTransactionError(
            "prepared publication has an invalid parent binding"
        )
    return {key: prepared[key] for key in fields if key in prepared}


def inspect_prepared_transaction(transaction_id: str) -> dict:
    """Authenticate and classify PREPARED targets without consulting candidates."""
    prepared, terminal = _prepared_transaction(transaction_id)
    if terminal is not None:
        return {
            "transaction_id": transaction_id, "state": terminal.get("state"),
            "terminal": terminal, "recoverable": False,
        }
    try:
        binding = _prepared_binding(prepared)
        inspected = publication_recovery.inspect(prepared)
    except Exception as exc:
        return {
            "transaction_id": transaction_id, "state": "PREPARED",
            "classification": "invalid", "members": [], "recoverable": False,
            "error": str(exc),
        }
    return {
        "transaction_id": transaction_id, "state": "PREPARED",
        "classification": inspected["classification"],
        "members": inspected["members"],
        "recoverable": inspected["classification"] in {"before", "after", "mixed"},
        "atomicity": ATOMICITY, "visibility": VISIBILITY, **binding,
    }


def _recovery_terminal(
    prepared: Mapping, state: str, *, error: str = "", rollback_errors=None,
) -> dict:
    try:
        binding = _prepared_binding(prepared)
    except Exception:
        binding = {}
    return _terminal_record(
        prepared["transaction_id"], state, list(prepared.get("operations") or []),
        error=error, rollback_errors=rollback_errors, recovered=True,
        binding=binding,
        plan_sha256=str(prepared.get("plan_sha256") or ""),
        transaction_id=recovery_contracts.publication_terminal_transaction_id(
            prepared["transaction_id"], state,
        ),
    )


def recover_prepared_transaction(transaction_id: str, action: str = "rollback") -> dict:
    """Finalize observed after-state or conservatively restore exact before-state."""
    if action not in {"rollback", "finalize-observed"}:
        raise file_ops.FileOperationError(
            "prepared recovery action must be rollback or finalize-observed"
        )
    try:
        transaction_id = recovery_contracts.exact_transaction_id(
            transaction_id, field="prepared transaction id",
        )
    except ValueError as exc:
        raise file_ops.FileOperationError(str(exc)) from exc
    prepared, terminal = _prepared_transaction(transaction_id)
    if terminal is not None:
        return terminal
    try:
        publication_recovery.preflight(prepared, action)
    except Exception:
        # Unlocked evidence is advisory. The authoritative re-read under the
        # transaction boundary below alone may authorize mutation or terminal
        # publication.
        pass
    # The transaction lock serializes the authoritative oplog re-read, all
    # target mutation, and the deterministic terminal append.
    with store.Lock("publication-recovery-" + transaction_id, timeout=10.0):
        prepared, terminal = _prepared_transaction(transaction_id)
        if terminal is not None:
            return terminal
        try:
            if action == "rollback":
                recovered = publication_recovery.rollback(
                    prepared, transaction_lock_held=True,
                    terminal_writer=lambda state: _recovery_terminal(
                        prepared, state, rollback_errors=[],
                    ),
                    authority_reader=lambda: _prepared_transaction(transaction_id),
                )
                return recovered["terminal"]
            finalized = publication_recovery.finalize_observed(
                prepared, transaction_lock_held=True,
                terminal_writer=lambda state: _recovery_terminal(prepared, state),
                authority_reader=lambda: _prepared_transaction(transaction_id),
            )
            return finalized["terminal"]
        except (file_ops.PreparedRecoveryBlocked,
                file_ops.PreparedFinalizeNotAllAfter,
                file_ops.PreparedFinalizeAfterRollbackStarted):
            raise
        except Exception as exc:
            # Before a valid recovery journal exists, invalid evidence retains
            # the legacy deterministic NEEDS_ATTENTION terminal behavior.
            try:
                journal = publication_recovery.load_manifest(prepared)
            except Exception:
                journal = True
            if journal:
                raise file_ops.PreparedRecoveryBlocked(
                    "prepared recovery evidence or journal is invalid",
                    {"transaction_id": prepared["transaction_id"],
                     "recovery_state": "BLOCKED", "cause": str(exc),
                     "blocked": None, "manifest_revision": 0,
                     "process_outcome": outcomes.ProcessOutcome.NOT_APPLICABLE.value,
                     "publication_outcome":
                         outcomes.PublicationOutcome.NEEDS_ATTENTION.value,
                     "operation_outcome":
                         outcomes.CompositeOutcome.PROCESS_FAILED.value,
                     "outcome": outcomes.CompositeOutcome.PROCESS_FAILED.value,
                     "outcome_known": True},
                ) from exc
            return _recovery_terminal(
                prepared, "NEEDS_ATTENTION", error=str(exc), rollback_errors=[],
            )


def recover_staged_batch_publication(transaction_id: str, **_kwargs) -> dict:
    """Deprecated fail-closed shim: PREPARED roll-forward is unavailable."""
    prepared, terminal = _prepared_transaction(transaction_id)
    if terminal is not None:
        return terminal
    raise file_ops.PreparedRollForwardUnavailable(
        "automatic PREPARED roll-forward is unavailable; inspect and choose "
        "rollback or finalize-observed",
        {"transaction_id": prepared["transaction_id"],
         "available_actions": ["rollback", "finalize-observed"]},
    )


# Compact aliases used by integration callers.
build = build_publish_plan
validate = validate_publish_plan
recover = recover_prepared_transaction
