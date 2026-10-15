"""Bounded pending media operations; an operation ID is never proof of consent.

Hooks only record stat identities, never hash/copy large media. The CLI checks
identities again and performs any capture outside the hook's time budget.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import os
import re
import stat
import time
import uuid

from . import profiles, recovery_storage, store

SCHEMA = "agw.media-operation/v1"
TTL_SECONDS = 24 * 60 * 60
MAX_RECORDS = 256
MAX_RECORD_BYTES = 32 * 1024
_ACTIVE = ContextVar("agw_media_continuation", default=None)


class MediaReviewError(RuntimeError):
    error_code = "media_operation_blocked"

    def __init__(self, message, details=None):
        super().__init__(message)
        self.details = details or {}


class MediaReviewRequired(MediaReviewError):
    error_code = "media_review_required"


class MediaCapacityBlocked(MediaReviewError):
    error_code = "media_capacity_blocked"


def is_media(path):
    return os.path.splitext(path)[1].lower() in recovery_storage.MEDIA_EXTENSIONS


def parent_binding(path):
    """Bind every directory component; refuse symlinks and reparse points."""
    result = []
    parent = os.path.dirname(os.path.abspath(path))
    while True:
        st = os.lstat(parent)
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) \
                or getattr(st, "st_file_attributes", 0) & 0x400:
            raise MediaReviewError("Media operations require ordinary local parent directories.")
        result.append([parent, st.st_dev, st.st_ino])
        next_parent = os.path.dirname(parent)
        if next_parent == parent:
            return result
        parent = next_parent


def identity(path):
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) \
            or getattr(st, "st_file_attributes", 0) & 0x400 \
            or profiles.is_placeholder(path, st=st) or profiles.is_sync_artifact(path):
        raise MediaReviewError("Media operations require an ordinary, locally available file.")
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]


def _root():
    root = os.path.join(store.agw_home(), "media-operations")
    os.makedirs(root, mode=0o700, exist_ok=True)
    parent_binding(os.path.join(root, "record"))
    return root


def _path(operation_id):
    if not isinstance(operation_id, str) or not re.fullmatch(r"[0-9a-f]{32}", operation_id):
        raise MediaReviewError("Invalid media operation ID.")
    return os.path.join(_root(), operation_id + ".json")


def _digest(plan):
    return hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def read(operation_id):
    path = _path(operation_id)
    if os.path.islink(path) or os.path.getsize(path) > MAX_RECORD_BYTES:
        raise MediaReviewError("Invalid media operation record.")
    with open(path, encoding="utf-8") as handle:
        record = json.load(handle)
    if not isinstance(record, dict) or not isinstance(record.get("plan"), dict):
        raise MediaReviewError("Invalid media operation record.")
    plan = record.get("plan", {})
    if plan.get("schema") != SCHEMA or plan.get("id") != operation_id \
            or record.get("plan_sha256") != _digest(plan):
        raise MediaReviewError("Media operation record failed integrity verification.")
    return record


def write(record):
    path = _path(record["plan"]["id"])
    temporary = path + "." + uuid.uuid4().hex + ".tmp"
    payload = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    if len(payload.encode()) > MAX_RECORD_BYTES:
        raise MediaReviewError("Media operation record exceeds its metadata limit.")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            fd = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def describe(record):
    plan = record["plan"]
    actions = ["replace", "save-separately", "cancel"] if plan["operation"] == "replace" \
        else ["archive", "cancel"]
    if record["state"] == "capacity-blocked":
        actions = [action for action in actions if action in {"save-separately", "cancel"}]
        instruction = (
            "Offer only the listed choices. Use their continue_argv with this same ID; "
            "do not retry replacement or prepare another operation to keep both. "
            "separate_result gives the actual output path and whether an existing file is reused. "
            "Explain briefly that the original is unchanged and ask only for the remaining choice."
        )
    elif record["state"] != "pending":
        actions = []
        instruction = "No continuation is available. Inspect the result and recovery transaction; do not replay."
    else:
        instruction = (
            "Reuse an explicit user choice for this exact target, action and recovery behavior. "
            "'Replace and keep a recovery copy' needs no second confirmation; 'use the new cover' "
            "leaves recovery undecided, so ask once. An ID does not prove consent. "
            "Use the chosen continue_argv, not the original overwrite. If supplied_stage is empty, "
            "create the finished replacement at staged_path without overwriting; otherwise preserve "
            "that supplied version. separate_result gives the actual keep-both path and whether "
            "it reuses an existing file. Cancel changes no files. Handle other targets separately."
        )
    return {
        **plan, "state": record["state"], "requires_user_choice": bool(actions),
        "approval_verified": False, "choices": actions,
        "continue_argv": {action: ["agw", "media", "continue", plan["id"],
                                    "--action", action, "--json"] for action in actions},
        "separate_result": {
            "path": plan["separate_path"],
            "reuses_existing_file": bool(plan.get("reuse_supplied_stage")),
        } if plan["operation"] == "replace" else None,
        "recovery": "Replacement/removal requires verified recovery within current budgets. "
                    "No permanent-delete option. No automatic expiration of the sole recovery copy.",
        "instruction": instruction,
    }


def prepare(target, policy_revision, *, operation="replace", staged=""):
    if operation not in {"replace", "archive"} or not policy_revision:
        raise MediaReviewError("A valid operation and current policy are required.")
    target = os.path.abspath(os.path.expanduser(target))
    if not is_media(target) or any(c in target for c in "\x00\n\r*?["):
        raise MediaReviewError("Prepare requires one literal media file path.")
    target_state = identity(target)
    parents = parent_binding(target)
    staged = os.path.abspath(os.path.expanduser(staged)) if staged else ""
    if staged:
        if operation != "replace" or os.path.samefile(target, staged):
            raise MediaReviewError("Replacement must be a distinct ordinary file.")
        parent_binding(staged)
        staged_state = identity(staged)
        staged_hash = store.file_sha256(staged)
        if identity(staged) != staged_state:
            raise MediaReviewError("Replacement changed while preparing; prepare again.")
    else:
        staged_state, staged_hash = None, ""
    with store.hook_lock("media-operations"):
        # Bound both storage and scan work. Expiration removes only metadata.
        names = []
        with os.scandir(_root()) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > MAX_RECORDS:
                    raise MediaReviewError("Pending-media metadata limit reached; inspect agw media status.")
        count = 0
        finished = []
        now = time.time()
        for name in names:
            if not re.fullmatch(r"[0-9a-f]{32}\.json", name):
                count += 1
                continue
            old = read(name[:-5])
            old_plan = old["plan"]
            if now >= old_plan["expires_at"] and old["state"] != "claimed":
                os.unlink(_path(name[:-5]))
                continue
            count += 1
            if old["state"] in {"completed", "cancelled"}:
                finished.append((old_plan["expires_at"], name[:-5]))
            if old["state"] == "pending" and old_plan["target"] == target \
                    and old_plan["target_identity"] == target_state \
                    and old_plan["parents"] == parents \
                    and old_plan["policy_revision"] == policy_revision \
                    and old_plan["operation"] == operation \
                    and old_plan["supplied_stage"] == staged \
                    and old_plan["stage_identity"] == staged_state \
                    and old_plan["stage_sha256"] == staged_hash:
                return describe(old)
        # Completed/cancelled receipts are not recovery artifacts. Retire the
        # oldest metadata under pressure; an unknown ID still cannot replay.
        for _, old_id in sorted(finished):
            if count < MAX_RECORDS:
                break
            os.unlink(_path(old_id))
            count -= 1
        if count >= MAX_RECORDS:
            raise MediaReviewError("Pending-media metadata limit reached; wait for record expiration.")
        operation_id = uuid.uuid4().hex
        stem, extension = os.path.splitext(os.path.basename(target))
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))
        reuse_stage = bool(staged and os.path.dirname(staged) == os.path.dirname(target))
        separate = staged if reuse_stage else os.path.join(
            os.path.dirname(target), f"{stem[:100]}-{stamp}-{operation_id[:8]}{extension}")
        candidate = staged or os.path.join(os.path.dirname(target), f".agw-media-{operation_id}{extension}")
        if (not reuse_stage and os.path.lexists(separate)) \
                or (not staged and os.path.lexists(candidate)):
            raise MediaReviewError("Proposed output already exists; prepare again.")
        plan = {
            "schema": SCHEMA, "id": operation_id, "operation": operation,
            "target": target, "target_identity": target_state, "parents": parents,
            "policy_revision": policy_revision, "expires_at": now + TTL_SECONDS,
            "staged_path": candidate, "separate_path": separate,
            "supplied_stage": staged, "stage_identity": staged_state,
            "stage_sha256": staged_hash,
            "stage_parents": parent_binding(candidate),
            "reuse_supplied_stage": reuse_stage,
        }
        record = {"plan": plan, "plan_sha256": _digest(plan), "state": "pending"}
        write(record)
        return describe(record)


def validate_target(plan, policy_revision):
    if plan["policy_revision"] != policy_revision:
        raise MediaReviewError("Policy changed; prepare a new media operation.")
    if parent_binding(plan["target"]) != plan["parents"] \
            or identity(plan["target"]) != plan["target_identity"]:
        raise MediaReviewError("Original media changed; prepare a new operation and clarify again.")


def require_review(targets, policy_revision, *, operation="replace", staged=""):
    active = _ACTIVE.get()
    for target in targets:
        target = os.path.abspath(target)
        if not is_media(target) or not os.path.lexists(target):
            continue
        if active and target == active["target"] and operation == active["operation"]:
            validate_target(active, policy_revision)
            continue
        pending = prepare(target, policy_revision, operation=operation, staged=staged)
        raise MediaReviewRequired(
            "Media operation paused; nothing was changed. Continue using an already-explicit "
            "user choice for this exact target, action and recovery behavior. A generic request "
            "to update or replace a file does not choose recovery versus keeping both. "
            "If that choice is missing, ask the user. Do not retry the original operation. "
            + json.dumps(pending, ensure_ascii=False, separators=(",", ":")),
            pending,
        )


@contextmanager
def continuation(plan):
    """Internal execution scope, not a flag/environment approval bypass."""
    token = _ACTIVE.set(plan)
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def capture_limit(targets):
    active = _ACTIVE.get()
    if active and list(targets) == [active["target"]]:
        # Long capture occurs in the CLI; archive/class budgets still apply.
        return max(1, active["target_identity"][2])
    return 0
