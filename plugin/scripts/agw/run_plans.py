"""Canonical, fresh, single-use plans for bounded local script execution."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import shutil
import stat
import sys
import time
import uuid
from typing import Callable, Mapping, Optional

from core import outcomes, recovery_contracts, store, workflows
import execution
import file_ops
import path_safety
import publication


RUN_PLAN_SCHEMA = "agw-run-plan/v1"
DEFAULT_LIFETIME_SECONDS = 30 * 60
MAX_LIFETIME_SECONDS = 24 * 60 * 60
FUTURE_SKEW_SECONDS = 5 * 60
MAX_ARTIFACTS = 64
MAX_ROOTS = 16
MAX_PATTERNS = 64
MAX_ARGS = 128
MAX_ARG_BYTES = 16 * 1024
CONSUMPTION_LOG = "run-plan-consumptions.jsonl"

_PLAN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_TOP_KEYS = {
    "schema", "mode", "freshness", "cwd", "command", "artifacts",
    "observed_roots", "execution", "plan_sha256",
}
_FRESHNESS_KEYS = {"plan_id", "issued_at_utc", "expires_at_utc", "max_uses"}
_COMMAND_KEYS = {"runtime", "script", "script_sha256", "args"}
_ARTIFACT_KEYS = {
    "number", "staged", "staged_before", "target", "target_before", "validation",
}
_VALIDATION_KEYS = {
    "kind", "tier", "preserve_against", "preserve_against_sha256",
}
_ROOT_KEYS = {"path", "patterns"}
_EXECUTION_KEYS = {"provider", "timeout_seconds", "isolation", "network"}


class RunPlanError(RuntimeError):
    error_code = "run_plan_error"

    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.details = details or {}


class RunPlanConflict(RunPlanError):
    error_code = "run_plan_conflict"


class RunPlanConsumed(RunPlanError):
    error_code = "run_plan_consumed"


class RunPlanExpired(RunPlanError):
    error_code = "run_plan_expired"


class ProviderResultInvalid(execution.ExecutionError):
    error_code = "provider_result_invalid"


def _exact(value, keys: set[str], label: str) -> Mapping:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise RunPlanError(f"{label} fields are invalid")
    return value


def _absolute_literal(value: object, label: str, *, directory: bool = False) -> str:
    if not isinstance(value, str) or not value or "\x00" in value \
            or any(char in value for char in "*?["):
        raise RunPlanError(f"{label} must be a literal path")
    result = os.path.abspath(os.path.expanduser(value))
    if directory and not os.path.isdir(result):
        raise RunPlanError(f"{label} must be an existing directory")
    return result


def _state(path: str) -> str:
    if not os.path.lexists(path):
        return "absent"
    try:
        item = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise RunPlanError(f"path state could not be inspected: {path}: {exc}") from exc
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode):
        raise RunPlanError(f"plan paths must be ordinary files or absent: {path}")
    return store.file_sha256(path)


def _hash(value: object, label: str, *, absent: bool = False) -> str:
    candidate = str(value or "").lower()
    if absent and candidate == "absent":
        return candidate
    if not _HASH_RE.fullmatch(candidate):
        raise RunPlanError(f"{label} must be a lowercase SHA-256" + (
            " or 'absent'" if absent else ""
        ))
    return candidate


def _validation(value: object) -> dict:
    if value is None or value == "raw":
        return {
            "kind": "raw", "tier": "binary", "preserve_against": "",
            "preserve_against_sha256": "",
        }
    supplied = _exact(value, _VALIDATION_KEYS, "artifact validation")
    kind = supplied.get("kind")
    tier = supplied.get("tier")
    if kind not in {"raw", "office"} or not isinstance(tier, str) or not tier:
        raise RunPlanError("artifact validation kind or tier is invalid")
    preserve = supplied.get("preserve_against")
    preserve_hash = supplied.get("preserve_against_sha256")
    if preserve:
        preserve = _absolute_literal(preserve, "preserve-against")
        preserve_hash = _hash(preserve_hash, "preserve-against hash")
    elif preserve_hash:
        raise RunPlanError("preserve-against hash requires a preserve-against path")
    return {
        "kind": kind, "tier": tier, "preserve_against": preserve or "",
        "preserve_against_sha256": preserve_hash or "",
    }


def _normalize_roots(values: object, cwd: str) -> list[dict]:
    if not isinstance(values, list) or len(values) > MAX_ROOTS:
        raise RunPlanError(f"observed roots must contain at most {MAX_ROOTS} entries")
    normalized = []
    paths = []
    for item in values:
        item = _exact(item, _ROOT_KEYS, "observed root")
        raw_path = item.get("path")
        path = raw_path if os.path.isabs(str(raw_path or "")) else os.path.join(cwd, str(raw_path or ""))
        path = _absolute_literal(path, "observed root", directory=True)
        patterns = item.get("patterns")
        if not isinstance(patterns, list) or len(patterns) > MAX_PATTERNS:
            raise RunPlanError(f"observed-root patterns must contain at most {MAX_PATTERNS} entries")
        clean = []
        for pattern in patterns:
            if not isinstance(pattern, str) or not pattern or "\x00" in pattern \
                    or os.path.isabs(pattern) or any(part == ".." for part in pattern.replace("\\", "/").split("/")):
                raise RunPlanError("observed patterns must be non-empty relative patterns without '..'")
            clean.append(pattern.replace("\\", "/"))
        if len(clean) != len(set(clean)):
            raise RunPlanError("observed patterns must be unique")
        normalized.append({"path": path, "patterns": clean})
        paths.append(path)
    try:
        path_safety.require_unique(paths, label="observed roots")
    except path_safety.PathSafetyError as exc:
        raise RunPlanError(str(exc), exc.details) from exc
    return normalized


def _launcher(command: Mapping) -> list[str]:
    runtime, script, args = command["runtime"], command["script"], list(command["args"])
    if runtime == "python":
        return [sys.executable, script, *args]
    if runtime == "node":
        executable = shutil.which("node") or shutil.which("nodejs")
    else:
        executable = shutil.which("pwsh") or shutil.which("powershell")
    if not executable:
        raise RunPlanError(f"the required {runtime} runtime is unavailable")
    return [executable, script, *args] if runtime == "node" else [
        executable, "-NoProfile", "-File", script, *args,
    ]


def _normalize_command(command: list[str], cwd: str) -> dict:
    try:
        normalized = workflows.normalize_command(command, cwd)
    except workflows.WorkflowError as exc:
        raise RunPlanError(str(exc), exc.details) from exc
    args = normalized["args"]
    if len(args) > MAX_ARGS or any(
        not isinstance(item, str) or "\x00" in item
        or len(item.encode("utf-8")) > MAX_ARG_BYTES for item in args
    ):
        raise RunPlanError("command arguments exceed literal argument bounds")
    return {
        "runtime": normalized["runtime"], "script": normalized["script"],
        "script_sha256": normalized["script_sha256"], "args": list(args),
    }


def create_run_plan(
    command: list[str], *, mode: str, cwd: str = "", artifacts: Optional[list[dict]] = None,
    observed_roots: Optional[list[dict]] = None, timeout_seconds: float = 300.0,
    isolation: str = "observed", network: str = "inherit", provider: str = "installed",
    issued_at_utc: Optional[float] = None, expires_at_utc: Optional[float] = None,
    plan_id: str = "",
) -> dict:
    """Create a hash-bound run plan from current local script and path state."""
    working = _absolute_literal(cwd or os.getcwd(), "cwd", directory=True)
    normalized_command = _normalize_command(command, working)
    if mode not in {"staged-publish", "stdout-read-only"}:
        raise RunPlanError("run plan mode must be staged-publish or stdout-read-only")
    if not isinstance(provider, str) or not provider or len(provider) > 64:
        raise RunPlanError("execution provider label is invalid")
    if isinstance(timeout_seconds, bool):
        raise RunPlanError("timeout must be a finite number")
    try:
        timeout = float(timeout_seconds)
    except (TypeError, ValueError) as exc:
        raise RunPlanError("timeout must be a finite number") from exc
    if not math.isfinite(timeout) or not 0 < timeout <= execution.MAX_TIMEOUT_SECONDS:
        raise RunPlanError("timeout is outside the supported bounds")
    if isolation not in {"observed", "read-only", "strict"} or network not in {"inherit", "deny"}:
        raise RunPlanError("execution isolation or network policy is invalid")

    supplied_artifacts = list(artifacts or [])
    roots = _normalize_roots(list(observed_roots or []), working)
    planned_artifacts = []
    if mode == "stdout-read-only":
        if supplied_artifacts or roots or isolation != "read-only":
            raise RunPlanError("stdout-read-only requires no artifacts or observed roots and read-only isolation")
    else:
        if not 1 <= len(supplied_artifacts) <= MAX_ARTIFACTS:
            raise RunPlanError(f"staged-publish requires 1 to {MAX_ARTIFACTS} artifacts")
        paths = []
        for number, supplied in enumerate(supplied_artifacts, 1):
            if not isinstance(supplied, Mapping):
                raise RunPlanError("each artifact must be an object")
            unknown = set(supplied) - {"staged", "target", "staged_before", "target_before", "validation"}
            if unknown:
                raise RunPlanError("artifact contains unknown fields")
            staged_raw, target_raw = supplied.get("staged"), supplied.get("target")
            staged = staged_raw if os.path.isabs(str(staged_raw or "")) else os.path.join(working, str(staged_raw or ""))
            target = target_raw if os.path.isabs(str(target_raw or "")) else os.path.join(working, str(target_raw or ""))
            staged = _absolute_literal(staged, "staged artifact")
            target = _absolute_literal(target, "target artifact")
            if not os.path.isdir(os.path.dirname(staged)) or not os.path.isdir(os.path.dirname(target)):
                raise RunPlanError("artifact parent directories must exist")
            staged_before, target_before = _state(staged), _state(target)
            if supplied.get("staged_before") and _hash(supplied["staged_before"], "staged-before", absent=True) != staged_before:
                raise RunPlanConflict("staged artifact does not match expected state")
            if supplied.get("target_before") and _hash(supplied["target_before"], "target-before", absent=True) != target_before:
                raise RunPlanConflict("target artifact does not match expected state")
            planned_artifacts.append({
                "number": number, "staged": staged, "staged_before": staged_before,
                "target": target, "target_before": target_before,
                "validation": _validation(supplied.get("validation")),
            })
            paths.extend((staged, target))
        try:
            path_safety.require_unique(paths, label="run-plan artifact paths")
        except path_safety.PathSafetyError as exc:
            raise RunPlanError(str(exc), exc.details) from exc

    issued = time.time() if issued_at_utc is None else issued_at_utc
    expires = issued + DEFAULT_LIFETIME_SECONDS if expires_at_utc is None else expires_at_utc
    if isinstance(issued, bool) or not isinstance(issued, (int, float)) \
            or isinstance(expires, bool) or not isinstance(expires, (int, float)):
        raise RunPlanError("freshness timestamps must be epoch seconds")
    identifier = plan_id or uuid.uuid4().hex
    plan = recovery_contracts.bind_plan_hash({
        "schema": RUN_PLAN_SCHEMA, "mode": mode,
        "freshness": {
            "plan_id": identifier, "issued_at_utc": issued,
            "expires_at_utc": expires, "max_uses": 1,
        },
        "cwd": working, "command": normalized_command,
        "artifacts": planned_artifacts, "observed_roots": roots,
        "execution": {
            "provider": provider, "timeout_seconds": timeout,
            "isolation": isolation, "network": network,
        },
    })
    return validate_run_plan(plan, check_freshness=False)


def validate_run_plan(plan: Mapping, *, expected_plan_hash: str = "", now: Optional[float] = None,
                      check_freshness: bool = True) -> dict:
    """Strictly validate and normalize one canonical run plan."""
    plan = _exact(plan, _TOP_KEYS, "run plan")
    if plan.get("schema") != RUN_PLAN_SCHEMA or not recovery_contracts.plan_hash_valid(plan):
        raise RunPlanError("run plan schema or canonical self-hash is invalid")
    actual_hash = _hash(plan.get("plan_sha256"), "plan hash")
    if expected_plan_hash and not hmac.compare_digest(actual_hash, _hash(expected_plan_hash, "expected plan hash")):
        raise RunPlanConflict("run plan does not match the expected hash")
    freshness = _exact(plan.get("freshness"), _FRESHNESS_KEYS, "freshness")
    identifier = freshness.get("plan_id")
    issued, expires = freshness.get("issued_at_utc"), freshness.get("expires_at_utc")
    if not isinstance(identifier, str) or not _PLAN_ID_RE.fullmatch(identifier):
        raise RunPlanError("plan_id must be 32 lowercase hexadecimal characters")
    if isinstance(issued, bool) or not isinstance(issued, (int, float)) or not math.isfinite(issued) \
            or isinstance(expires, bool) or not isinstance(expires, (int, float)) or not math.isfinite(expires):
        raise RunPlanError("freshness timestamps must be finite epoch seconds")
    if expires < issued or expires - issued > MAX_LIFETIME_SECONDS or freshness.get("max_uses") != 1:
        raise RunPlanError("freshness bounds or max_uses are invalid")
    current = time.time() if now is None else now
    if check_freshness and (issued > current + FUTURE_SKEW_SECONDS or expires < current):
        raise RunPlanExpired("run plan is not currently fresh")
    cwd = _absolute_literal(plan.get("cwd"), "cwd", directory=True)
    if cwd != plan.get("cwd"):
        raise RunPlanError("cwd must be a normalized absolute path")
    command = _exact(plan.get("command"), _COMMAND_KEYS, "command")
    if command.get("runtime") not in {"python", "node", "powershell"}:
        raise RunPlanError("command runtime is invalid")
    script = _absolute_literal(command.get("script"), "script")
    if script != command.get("script") or _state(script) != _hash(command.get("script_sha256"), "script hash"):
        raise RunPlanConflict("script path or content no longer matches the plan")
    args = command.get("args")
    if not isinstance(args, list) or len(args) > MAX_ARGS or any(
        not isinstance(item, str) or "\x00" in item or len(item.encode("utf-8")) > MAX_ARG_BYTES
        for item in args
    ):
        raise RunPlanError("command arguments are not a bounded literal array")
    if _normalize_command(_launcher(command), cwd) != dict(command):
        raise RunPlanConflict("command is not the exact normalized local script invocation")
    execution_spec = _exact(plan.get("execution"), _EXECUTION_KEYS, "execution")
    provider = execution_spec.get("provider")
    timeout = execution_spec.get("timeout_seconds")
    if not isinstance(provider, str) or not provider or len(provider) > 64:
        raise RunPlanError("execution provider label is invalid")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) \
            or not 0 < timeout <= execution.MAX_TIMEOUT_SECONDS:
        raise RunPlanError("execution timeout is invalid")
    if execution_spec.get("isolation") not in {"observed", "read-only", "strict"} \
            or execution_spec.get("network") not in {"inherit", "deny"}:
        raise RunPlanError("execution isolation or network policy is invalid")
    roots = _normalize_roots(plan.get("observed_roots"), cwd)
    if roots != plan.get("observed_roots"):
        raise RunPlanError("observed roots must be normalized")
    artifacts = plan.get("artifacts")
    if not isinstance(artifacts, list):
        raise RunPlanError("artifacts must be an array")
    normalized_artifacts, paths = [], []
    for number, item in enumerate(artifacts, 1):
        item = _exact(item, _ARTIFACT_KEYS, "artifact")
        staged = _absolute_literal(item.get("staged"), "staged artifact")
        target = _absolute_literal(item.get("target"), "target artifact")
        if item.get("number") != number or staged != item.get("staged") or target != item.get("target"):
            raise RunPlanError("artifact numbering or normalized paths are invalid")
        normalized_artifacts.append({
            "number": number, "staged": staged,
            "staged_before": _hash(item.get("staged_before"), "staged-before", absent=True),
            "target": target,
            "target_before": _hash(item.get("target_before"), "target-before", absent=True),
            "validation": _validation(item.get("validation")),
        })
        paths.extend((staged, target))
    try:
        path_safety.require_unique(paths, label="run-plan artifact paths")
    except path_safety.PathSafetyError as exc:
        raise RunPlanError(str(exc), exc.details) from exc
    mode = plan.get("mode")
    if mode == "staged-publish":
        if not 1 <= len(normalized_artifacts) <= MAX_ARTIFACTS:
            raise RunPlanError(f"staged-publish requires 1 to {MAX_ARTIFACTS} artifacts")
    elif mode == "stdout-read-only":
        if normalized_artifacts or roots or execution_spec["isolation"] != "read-only":
            raise RunPlanError("stdout-read-only contract is invalid")
    else:
        raise RunPlanError("run plan mode is invalid")
    return dict(plan)


def _consumption_path() -> str:
    return os.path.join(store.agw_home(), CONSUMPTION_LOG)


def _consumptions() -> list[dict]:
    path = _consumption_path()
    if not os.path.exists(path):
        return []
    records = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    value = json.loads(line)
                    if isinstance(value, dict):
                        records.append(value)
    except (OSError, ValueError) as exc:
        raise RunPlanError("run-plan consumption journal is unreadable") from exc
    return records


def _append_consumption(record: dict) -> None:
    path = _consumption_path()
    encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise OSError("short append to consumption journal")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise RunPlanError("run-plan consumption could not be recorded") from exc


def _claim_lock(plan_id: str) -> str:
    return "run-plan-" + hashlib.sha256(plan_id.encode("ascii")).hexdigest()[:32]


def _latest_claim(plan_id: str, plan_hash: str) -> Optional[dict]:
    matching = [item for item in _consumptions() if item.get("plan_id") == plan_id]
    if not matching:
        return None
    if any(item.get("plan_sha256") != plan_hash for item in matching):
        raise RunPlanConflict("plan_id is already bound to a different plan hash")
    return matching[-1]


def _claim(plan: Mapping) -> dict:
    plan_id, plan_hash = plan["freshness"]["plan_id"], plan["plan_sha256"]
    with store.Lock(_claim_lock(plan_id), timeout=10.0):
        if _latest_claim(plan_id, plan_hash) is not None:
            raise RunPlanConsumed("run plan was already claimed")
        record = {
            "schema": "agw-run-plan-consumption/v1", "state": "CLAIMED",
            "claim_id": uuid.uuid4().hex, "plan_id": plan_id,
            "plan_sha256": plan_hash, "claimed_at_utc": time.time(),
        }
        _append_consumption(record)
        return record


def _terminal(claim: Mapping, state: str, **details) -> None:
    with store.Lock(_claim_lock(claim["plan_id"]), timeout=10.0):
        current = _latest_claim(claim["plan_id"], claim["plan_sha256"])
        if not current or current.get("claim_id") != claim["claim_id"] or current.get("state") != "CLAIMED":
            raise RunPlanConflict("active run-plan claim changed before terminal recording")
        _append_consumption({
            **dict(claim), "state": state, "terminal_at_utc": time.time(), **details,
        })


def _claim_validator(parent: Mapping, claim: Mapping, _child: Mapping, phase: str) -> bool:
    if phase not in {"pre_lock", "under_lock"}:
        return False
    plan_id, plan_hash = parent["freshness"]["plan_id"], parent["plan_sha256"]
    with store.Lock(_claim_lock(plan_id), timeout=10.0):
        current = _latest_claim(plan_id, plan_hash)
        return bool(current and current.get("state") == "CLAIMED"
                    and current.get("claim_id") == claim.get("claim_id"))


def _preconditions(plan: Mapping) -> None:
    if _state(plan["command"]["script"]) != plan["command"]["script_sha256"]:
        raise RunPlanConflict("script changed after planning")
    for item in plan["artifacts"]:
        if _state(item["staged"]) != item["staged_before"]:
            raise RunPlanConflict("staged artifact changed after planning", {"path": item["staged"]})
        if _state(item["target"]) != item["target_before"]:
            raise RunPlanConflict("target artifact changed after planning", {"path": item["target"]})
        validation = item["validation"]
        if validation["preserve_against"] and _state(validation["preserve_against"]) != validation["preserve_against_sha256"]:
            raise RunPlanConflict("preserve-against artifact changed after planning")


def _environment_failure(reason: str, error_code: str = "isolation_unavailable") -> dict:
    return outcomes.completed_record({
        "ok": False, "executed": False, "execution_started": False,
        "fallback_performed": False, "error": reason, "error_code": error_code,
        "environment_outcome": outcomes.EnvironmentOutcome.FAILED.value,
        "process_outcome": outcomes.ProcessOutcome.NOT_STARTED.value,
        "contract_outcome": outcomes.ContractOutcome.NOT_EVALUATED.value,
        "publication_outcome": outcomes.PublicationOutcome.NOT_ATTEMPTED.value,
        "recovery_state": "NOT_STARTED", "claimed": False, "consumed": False,
    })


def _provider_ready(plan: Mapping, provider_object) -> tuple[object, Optional[dict]]:
    spec = plan["execution"]
    provider_object = provider_object or execution.DEFAULT_RUNNER
    caps = getattr(provider_object, "capabilities", None)
    if caps is None or caps.script_execution_integrity != "verified-immutable":
        return provider_object, _environment_failure(
            "the provider cannot prove immutable script execution",
            "immutable_execution_unavailable",
        )
    identity = caps.provider_identity
    if not identity or identity != spec["provider"]:
        return provider_object, _environment_failure(
            "the plan execution provider does not match the selected provider",
            "execution_provider_mismatch",
        )
    if spec["isolation"] not in caps.isolation_modes \
            or spec["network"] not in caps.network_policies:
        return provider_object, _environment_failure(
            "the requested execution isolation is unavailable"
        )
    if plan["mode"] == "stdout-read-only" \
            and not caps.filesystem_enforcement:
        return provider_object, _environment_failure(
            "the provider cannot enforce a read-only filesystem"
        )
    if spec["network"] == "deny" \
            and not caps.network_enforcement:
        return provider_object, _environment_failure(
            "the provider cannot enforce network denial"
        )
    return provider_object, None


def _attest_result(result, plan: Mapping, provider_object) -> None:
    """Require result-level evidence; capability advertisements are insufficient."""
    if not isinstance(result, execution.ExecutionResult):
        raise ProviderResultInvalid(
            "execution provider returned a nonconforming result",
            {"execution_started": None, "fallback_performed": False},
        )
    spec = plan["execution"]
    caps = provider_object.capabilities
    checks = {
        "provider_identity": (caps.provider_identity, result.provider_identity),
        "script_execution_integrity": (
            "verified-immutable", result.script_execution_integrity,
        ),
        "isolation_mode": (spec["isolation"], result.isolation_mode),
        "network_policy": (spec["network"], result.network_policy),
        "filesystem_enforcement": (
            caps.filesystem_enforcement, result.filesystem_enforcement,
        ),
        "network_enforcement": (
            caps.network_enforcement, result.network_enforcement,
        ),
    }
    mismatched = {
        name: {"expected": expected, "actual": actual}
        for name, (expected, actual) in checks.items() if actual != expected
    }
    consistency = {}
    if type(result.execution_started) is not bool:
        consistency["execution_started"] = "must be boolean"
    if type(result.fallback_performed) is not bool:
        consistency["fallback_performed"] = "must be boolean"
    elif result.fallback_performed:
        consistency["fallback_performed"] = "fallback is forbidden"
    if type(result.timed_out) is not bool:
        consistency["timed_out"] = "must be boolean"
    if type(result.exit_code) is not int:
        consistency["exit_code"] = "must be an integer"
    process = result.process_outcome
    if result.execution_started is False:
        if process != outcomes.ProcessOutcome.NOT_STARTED.value:
            consistency["process_outcome"] = "not-started execution must report not_started"
        if result.exit_code != -1:
            consistency["exit_code"] = "not-started execution must use the no-exit sentinel"
        if result.timed_out is not False:
            consistency["timed_out"] = "not-started execution cannot time out"
    elif result.execution_started is True:
        if process not in {
            outcomes.ProcessOutcome.SUCCEEDED.value,
            outcomes.ProcessOutcome.FAILED.value,
            outcomes.ProcessOutcome.TIMED_OUT.value,
        }:
            consistency["process_outcome"] = "started execution needs a terminal process outcome"
        elif process == outcomes.ProcessOutcome.SUCCEEDED.value:
            if result.exit_code != 0 or result.timed_out:
                consistency["success"] = "success requires exit zero without timeout"
        elif process == outcomes.ProcessOutcome.FAILED.value:
            if result.exit_code == 0 or result.timed_out:
                consistency["failure"] = "failure requires nonzero exit without timeout"
        elif process == outcomes.ProcessOutcome.TIMED_OUT.value:
            if result.exit_code == 0 or not result.timed_out:
                consistency["timeout"] = "timeout requires nonzero exit and timed_out=true"
    if mismatched or consistency:
        raise ProviderResultInvalid(
            "execution provider returned unverifiable or inconsistent result metadata",
            {"execution_started": None, "fallback_performed": False,
             "attestation_mismatches": mismatched,
             "consistency_errors": consistency},
        )


class _AttestingProvider:
    def __init__(self, provider_object, plan: Mapping):
        self._provider = provider_object
        self._plan = plan
        self.capabilities = provider_object.capabilities

    def run(self, request):
        try:
            result = self._provider.run(request)
        except execution.ExecutionError:
            raise
        except Exception as exc:
            raise execution.ExecutionError(
                "execution provider failed with unknown launch provenance",
                {"execution_started": None, "fallback_performed": False,
                 "provider_error": str(exc)},
            ) from exc
        _attest_result(result, self._plan, self._provider)
        return result


def _policy_allowed(plan: Mapping, validator: Optional[Callable[[Mapping], object]]) -> None:
    if validator is not None and validator(plan) is not True:
        raise RunPlanError("run plan was blocked by policy", {"policy_outcome": "blocked"})


def _error_code(exc: BaseException) -> str:
    current: Optional[BaseException] = exc
    while current is not None:
        if isinstance(current, ProviderResultInvalid):
            return ProviderResultInvalid.error_code
        current = current.__cause__
    return str(getattr(exc, "error_code", "run_failed"))


def apply_run_plan(
    plan: Mapping, *, expected_plan_hash: str = "", dry_run: bool = False,
    execution_provider=None, policy_validator: Optional[Callable[[Mapping], object]] = None,
    candidate_validator=None,
) -> dict:
    """Validate, claim once, execute, and conditionally publish a run plan."""
    validated = validate_run_plan(plan, expected_plan_hash=expected_plan_hash)
    _policy_allowed(validated, policy_validator)
    _preconditions(validated)
    if _latest_claim(validated["freshness"]["plan_id"], validated["plan_sha256"]) is not None:
        raise RunPlanConsumed("run plan was already claimed")
    if dry_run:
        return outcomes.completed_record({
            "ok": True, "dry_run": True, "executed": False,
            "execution_started": False, "fallback_performed": False,
            "process_outcome": outcomes.ProcessOutcome.NOT_APPLICABLE.value,
            "contract_outcome": outcomes.ContractOutcome.NOT_EVALUATED.value,
            "publication_outcome": (
                outcomes.PublicationOutcome.VALIDATED.value
                if validated["mode"] == "staged-publish"
                else outcomes.PublicationOutcome.NOT_ATTEMPTED.value
            ),
            "recovery_state": "NOT_STARTED", "claimed": False, "consumed": False,
            "plan_id": validated["freshness"]["plan_id"],
            "plan_sha256": validated["plan_sha256"],
        }, operation_outcome=outcomes.CompositeOutcome.SUCCESS)
    provider_object, unavailable = _provider_ready(validated, execution_provider)
    if unavailable is not None:
        return unavailable
    attesting_provider = _AttestingProvider(provider_object, validated)
    claim = _claim(validated)
    command = _launcher(validated["command"])
    spec = validated["execution"]
    try:
        if validated["mode"] == "stdout-read-only":
            completed = execution.run(execution.ExecutionRequest(
                command=command, cwd=validated["cwd"], timeout_seconds=spec["timeout_seconds"],
                isolation=execution.IsolationRequest(mode=spec["isolation"], network=spec["network"]),
            ), provider=attesting_provider)
            result = outcomes.completed_record({
                **completed.to_dict(), "executed": completed.execution_started,
                "contract_outcome": outcomes.ContractOutcome.SATISFIED.value,
                "claim_id": claim["claim_id"], "plan_sha256": validated["plan_sha256"],
            })
            _terminal(claim, "CONSUMED", outcome=result["outcome"])
            return result

        roots = [item["path"] for item in validated["observed_roots"]]
        patterns = [pattern for item in validated["observed_roots"] for pattern in item["patterns"]]
        staged = [item["staged"] for item in validated["artifacts"]]
        run = file_ops.run_declared(
            command, staged,
            expected_hashes=[item["staged_before"] for item in validated["artifacts"]],
            cwd=validated["cwd"], output_roots=roots, output_patterns=patterns,
            timeout_seconds=spec["timeout_seconds"], isolation_mode=spec["isolation"],
            network_policy=spec["network"], execution_provider=attesting_provider,
        )
        process = outcomes.ProcessOutcome.TIMED_OUT.value if run.get("timed_out") else (
            outcomes.ProcessOutcome.SUCCEEDED.value if run.get("exit_code") == 0
            else outcomes.ProcessOutcome.FAILED.value
        )
        contract = outcomes.ContractOutcome.EXTRA_OUTPUTS.value if run.get("unclaimed_observed_changes") else (
            outcomes.ContractOutcome.OUTPUT_MISMATCH.value if run.get("declared_outputs_missing")
            else outcomes.ContractOutcome.SATISFIED.value
        )
        evaluated = outcomes.completed_record({
            **run, "execution_started": True, "process_outcome": process,
            "contract_outcome": contract, "claim_id": claim["claim_id"],
            "plan_sha256": validated["plan_sha256"],
            "publication_outcome": outcomes.PublicationOutcome.NOT_ATTEMPTED.value,
        })
        if process != outcomes.ProcessOutcome.SUCCEEDED.value \
                or contract != outcomes.ContractOutcome.SATISFIED.value:
            _terminal(claim, "CONSUMED", outcome=evaluated["outcome"],
                      stage_transaction_id=run.get("transaction_id", ""))
            return evaluated

        binding = {
            "schema": RUN_PLAN_SCHEMA,
            "plan_id": validated["freshness"]["plan_id"],
            "plan_sha256": validated["plan_sha256"], "claim_id": claim["claim_id"],
        }
        child = publication.build_publish_plan([{
            "staged": item["staged"], "target": item["target"],
            "expected_hash": item["target_before"], "validation": item["validation"],
        } for item in validated["artifacts"]], cwd=validated["cwd"], parent=binding)
        published = publication.publish_staged_batch(
            child, expected_plan_hash=child["plan_sha256"],
            candidate_validator=candidate_validator, parent_plan=validated,
            parent_claim=claim, claim_validator=_claim_validator,
        )
        result = outcomes.completed_record({
            **evaluated, "ok": True, "publication": published,
            "stage_transaction_id": run.get("transaction_id", ""),
            "publication_transaction_id": published.get("transaction_id", ""),
            "publish_plan_sha256": child["plan_sha256"],
            "process_outcome": outcomes.ProcessOutcome.SUCCEEDED.value,
            "contract_outcome": outcomes.ContractOutcome.SATISFIED.value,
            "publication_outcome": outcomes.PublicationOutcome.COMMITTED.value,
        })
        _terminal(claim, "CONSUMED", outcome=result["outcome"],
                  stage_transaction_id=result["stage_transaction_id"],
                  publication_transaction_id=result["publication_transaction_id"],
                  publish_plan_sha256=child["plan_sha256"])
        return result
    except Exception as exc:
        error_code = _error_code(exc)
        try:
            _terminal(claim, "CONSUMED", outcome="failed", error_code=error_code)
        except Exception:
            pass
        details = getattr(exc, "details", {})
        evidence = details.get("execution_started")
        started = evidence if isinstance(evidence, bool) else None
        unknown = started is None
        return outcomes.completed_record({
            "ok": False, "executed": started,
            "execution_started": started,
            "fallback_performed": False, "error": str(exc),
            "error_code": error_code,
            "environment_outcome": outcomes.EnvironmentOutcome.FAILED.value
            if unknown or started is False else outcomes.EnvironmentOutcome.READY.value,
            "process_outcome": (
                outcomes.ProcessOutcome.UNKNOWN.value if unknown
                else outcomes.ProcessOutcome.FAILED.value if started
                else outcomes.ProcessOutcome.NOT_STARTED.value
            ),
            "contract_outcome": outcomes.ContractOutcome.INDETERMINATE.value
            if unknown else outcomes.ContractOutcome.NOT_EVALUATED.value,
            "publication_outcome": outcomes.PublicationOutcome.NOT_ATTEMPTED.value,
            "claim_id": claim["claim_id"], "plan_sha256": validated["plan_sha256"],
            "claimed": True, "consumed": True,
        })


__all__ = [
    "RUN_PLAN_SCHEMA", "RunPlanConflict", "RunPlanConsumed", "RunPlanError",
    "RunPlanExpired", "apply_run_plan", "create_run_plan", "validate_run_plan",
]
