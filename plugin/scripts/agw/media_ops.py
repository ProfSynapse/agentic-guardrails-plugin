"""Protected conversational media continuations.

The CLI never treats an operation ID or an agent assertion as human approval.
Every available action remains recoverable or preserves the original.
"""
from __future__ import annotations

from contextlib import ExitStack
import os
import shutil
import time

from core import engine, media_review as review, recovery_storage, store
import file_ops
import publication
import retention_config

PLUGIN_ROOT = file_ops.PLUGIN_ROOT


def prepare(target, *, operation="replace", staged=""):
    policy = engine.load_policy(PLUGIN_ROOT)
    return review.prepare(target, policy.revision, operation=operation, staged=staged)


def _stage(plan):
    path = plan["staged_path"]
    if review.parent_binding(path) != plan["stage_parents"]:
        raise review.MediaReviewError("Replacement parent changed; prepare again.")
    identity = review.identity(path)
    if os.path.samefile(path, plan["target"]) or os.stat(path).st_nlink != 1:
        raise review.MediaReviewError("Replacement must be independent of the original and other files.")
    digest = store.file_sha256(path)
    if review.identity(path) != identity or (plan["stage_identity"] is not None and (
            identity != plan["stage_identity"] or digest != plan["stage_sha256"])):
        raise review.MediaReviewError("Replacement changed; prepare again and clarify the new version.")
    return identity, digest


def _remove_owned_stage(plan, expected_identity, expected_hash):
    path = plan["staged_path"]
    if plan["supplied_stage"] or not os.path.lexists(path):
        return False
    if review.parent_binding(path) != plan["stage_parents"] \
            or review.identity(path) != expected_identity \
            or store.file_sha256(path) != expected_hash \
            or review.identity(path) != expected_identity:
        return False
    os.unlink(path)
    return True


def _save_separately(plan, stage_identity, stage_hash):
    paths = {plan["target"], plan["staged_path"], plan["separate_path"]}
    with ExitStack() as locks:
        for _, name in sorted(publication._lock_name(path) for path in paths):
            locks.enter_context(store.Lock(name, timeout=10.0))
        review.validate_target(plan, engine.load_policy(PLUGIN_ROOT).revision)
        if review.identity(plan["staged_path"]) != stage_identity:
            raise review.MediaReviewError("Replacement changed before separate publication.")
        return _save_separately_locked(plan, stage_identity, stage_hash)


def _save_separately_locked(plan, stage_identity, stage_hash):
    source, target = plan["staged_path"], plan["separate_path"]
    if review.parent_binding(target) != plan["parents"]:
        raise review.MediaReviewError("Output parent changed; prepare again.")
    if not plan["supplied_stage"]:
        # The planned stage and final name share a directory. link() is an
        # atomic no-clobber publication, unlike rename() on Unix. Removing the
        # owned stage afterward transfers its bytes without duplicating them.
        publication._fsync_file_and_parent(source)
        if review.identity(source) != stage_identity:
            raise review.MediaReviewError("Replacement changed before separate publication.")
        os.link(source, target, follow_symlinks=False)
        linked_identity = review.identity(source)
        if linked_identity[:4] != stage_identity[:4] \
                or not os.path.samefile(source, target) \
                or store.file_sha256(target) != stage_hash:
            raise review.MediaReviewError(
                "Separate output needs inspection; files were retained and this operation cannot replay."
            )
        publication._fsync_file_and_parent(target)
        if not _remove_owned_stage(plan, linked_identity, stage_hash):
            raise review.MediaReviewError("Separate output exists but its staging name could not be retired; inspect both files.")
    else:
        # A caller-supplied stage remains theirs. Never make the delivered
        # output an alias that later edits to that stage could corrupt.
        with open(source, "rb") as reader, open(target, "xb") as writer:
            shutil.copyfileobj(reader, writer, length=1024 * 1024)
            writer.flush()
            os.fsync(writer.fileno())
        if review.identity(source) != stage_identity or store.file_sha256(target) != stage_hash:
            raise review.MediaReviewError(
                "Separate output failed verification; inspect the retained output before using it."
            )
        publication._fsync_file_and_parent(target)
    return {"path": target, "changed": 1, "original_preserved": True,
            "after_hash": stage_hash, "staged_path": source,
            "stage_retained": os.path.lexists(source)}


def continue_operation(operation_id, action):
    if action not in {"replace", "save-separately", "archive", "cancel"}:
        raise review.MediaReviewError("Only protected media actions are supported.")
    review._path(operation_id)  # Validate before constructing a lock name.
    # Never hold the metadata-index lock while waiting for publication locks:
    # ordinary file operations may hold a file lock while preparing a review.
    # A fixed stripe set also bounds persistent kernel-lock gate files.
    slot = str(int(operation_id[:2], 16) % 64)
    with store.Lock("media-operation-slot-" + slot, timeout=10.0):
        record = review.read(operation_id)
        plan = record["plan"]
        if record["state"] != "pending":
            raise review.MediaReviewError("This media operation was already used. Inspect its status; do not replay it.")
        if time.time() >= plan["expires_at"]:
            raise review.MediaReviewError("Media operation expired; prepare again and clarify the current files.")
        choices = review.describe(record)["choices"]
        if action not in choices:
            raise review.MediaReviewError("The chosen action does not match this media operation.")
        if action == "cancel":
            record["state"] = "cancelled"
            with store.Lock("media-operations", timeout=10.0):
                review.write(record)
            return {"id": operation_id, "state": "cancelled", "changed": 0,
                    "staged_path": plan["staged_path"],
                    "message": "No files changed. Any staged output remains in place."}
        policy = engine.load_policy(PLUGIN_ROOT)
        review.validate_target(plan, policy.revision)
        resolved_retention = retention_config.load(PLUGIN_ROOT)
        if action in {"replace", "archive"}:
            bucket = recovery_storage.classify(plan["target"], rules=resolved_retention.storage_rules)
            limits = [resolved_retention.max_bytes] if not resolved_retention.unlimited else []
            if resolved_retention.separated and bucket in {"media", "derived"}:
                limits.append(getattr(resolved_retention, bucket + "_max_bytes"))
            if limits and plan["target_identity"][2] > min(limits):
                raise review.MediaReviewError(
                    "Original media exceeds its recovery allowance. Choose save-separately or cancel "
                    "for replacement, or cancel removal. Permanent replacement is unavailable.",
                    {"maximum_bytes": min(limits), "original_bytes": plan["target_identity"][2],
                     "id": operation_id, "state": "pending"},
                )
        target_hash = store.file_sha256(plan["target"]) if action == "replace" else ""
        review.validate_target(plan, policy.revision)
        stage_identity, stage_hash = _stage(plan) if action != "archive" else (None, "")
        # Claim durably before side effects. A crash or ambiguous failure cannot
        # replay an operation. Recovery uses the publication/archive journal.
        record.update(state="claimed", action=action)
        with store.Lock("media-operations", timeout=10.0):
            current = review.read(operation_id)
            if current["state"] != "pending" or time.time() >= plan["expires_at"]:
                raise review.MediaReviewError("Media operation is no longer pending and current; prepare again.")
            review.write(record)
        try:
            review.validate_target(plan, policy.revision)
            with review.continuation(plan):
                if action == "replace":
                    publish_plan = publication.build_publish_plan([{
                        "stage": plan["staged_path"], "target": plan["target"],
                        "expected_hash": target_hash, "expected_stage_hash": stage_hash,
                        "validation": "raw",
                    }])
                    result = publication.publish_staged_batch(
                        publish_plan, expected_plan_hash=publish_plan["plan_sha256"],
                    )
                    _remove_owned_stage(plan, stage_identity, stage_hash)
                    result["stage_retained"] = os.path.lexists(plan["staged_path"])
                elif action == "save-separately":
                    result = _save_separately(plan, stage_identity, stage_hash)
                else:
                    entry = store.archive_file(
                        plan["target"], mode="move", reason="conversational media removal",
                        actor="agw media", retention_class="safety_archive",
                        retention_config=resolved_retention,
                    )
                    result = {"changed": 1, "archive": entry,
                              "restore_argv": ["agw", "restore", plan["target"]]}
            record.update(state="completed", result=result)
            with store.Lock("media-operations", timeout=10.0):
                review.write(record)
        except Exception as exc:
            record.update(state="needs-inspection", error=str(exc)[:1000],
                          failure_details=getattr(exc, "details", {}))
            with store.Lock("media-operations", timeout=10.0):
                review.write(record)
            raise review.MediaReviewError(
                "Media continuation did not complete cleanly. The operation is consumed; "
                "inspect its status before preparing another. Permanent replacement was not enabled. "
                + str(exc),
                {"id": operation_id, "state": record["state"],
                 "cause_code": getattr(exc, "error_code", "media_operation_error"),
                 "cause_details": getattr(exc, "details", {})},
            ) from exc
        return {**result, "publication_state": result.get("state"),
                "id": operation_id, "state": "completed", "action": action}
