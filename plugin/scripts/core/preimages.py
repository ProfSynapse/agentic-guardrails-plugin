"""Verified pre-authorization recovery artifacts for local file mutations."""
from __future__ import annotations

from dataclasses import dataclass, field
import os
import shutil
import stat
import time
import uuid

from . import archive_transactions as archive_tx
from . import recovery_contracts
from . import retention_policy
from . import store


@dataclass(frozen=True)
class PreimageReceipt:
    target: str
    state: str
    artifact: str = ""
    sha256: str = ""
    identity: tuple = ()
    transaction_id: str = ""
    policy_revision: str = ""
    recovery_record_kind: str = ""
    recovery_record_state: str = ""

    def to_dict(self, undo_transaction_id: str = "") -> dict:
        """Return the receipt and its explicit recovery contract.

        Multi-file callers should pass their parent transaction id so the
        serialized undo command addresses the atomic mutation record.
        """
        contract = recovery_contracts.recovery_receipt_fields(
            target=self.target,
            state=self.state,
            artifact=self.artifact,
            transaction_id=self.transaction_id,
            recovery_record_kind=self.recovery_record_kind,
            recovery_record_state=self.recovery_record_state,
            undo_transaction_id=undo_transaction_id,
        )
        return {
            "target": self.target,
            "state": self.state,
            "artifact": self.artifact,
            "sha256": self.sha256,
            "identity": list(self.identity),
            "policy_revision": self.policy_revision,
            **contract,
        }


@dataclass
class PreimageResult:
    ok: bool
    receipts: list[PreimageReceipt] = field(default_factory=list)
    reason: str = ""
    failed_target: str = ""


def allocated_size(path: str, st=None) -> int:
    """Portable allocated-byte estimate; Windows has no ``st_blocks``."""
    st = st or os.stat(path, follow_symlinks=False)
    blocks = getattr(st, "st_blocks", None)
    if isinstance(blocks, int) and blocks > 0:
        return blocks * 512
    return int(getattr(st, "st_size", 0) or 0)


def _identity(st) -> tuple:
    return (
        getattr(st, "st_dev", None), getattr(st, "st_ino", None),
        getattr(st, "st_size", None), getattr(st, "st_mtime_ns", None),
        getattr(st, "st_ctime_ns", None),
    )


def _nearest_existing_parent(path: str) -> str:
    parent = os.path.dirname(path)
    while parent and not os.path.isdir(parent):
        previous = parent
        parent = os.path.dirname(parent)
        if parent == previous:
            break
    if not parent or not os.path.isdir(parent):
        raise OSError("the target's containing folder could not be verified")
    return os.path.realpath(parent)


def _plain_failure(path: str, detail: str) -> PreimageResult:
    name = os.path.basename(path) or path or "the target"
    return PreimageResult(
        False,
        reason=(f"Guardrails blocked this change because it could not create and verify "
                f"a recovery point for {name}. {detail} Nothing was changed by this operation."),
        failed_target=path,
    )


def prepare(targets, label: str, max_file_bytes: int,
            max_archive_bytes: int | None = None,
            policy_revision: str = "",
            retention_config: retention_policy.RetentionPolicy | None = None
            ) -> PreimageResult:
    """Capture and immediately verify PRESENT artifacts and ABSENT tombstones."""
    if not policy_revision:
        return PreimageResult(
            False,
            reason="Safety preauthorization failed because the policy revision was unavailable.",
        )
    try:
        retention_config = retention_config or retention_policy.resolve_retention_policy(
            ({"archive_max_bytes": max_archive_bytes}
             if max_archive_bytes is not None else {})
        )
    except retention_policy.RetentionPolicyError as exc:
        return PreimageResult(
            False,
            reason=("Safety preauthorization failed because the recovery-cache "
                    f"policy is invalid ({exc})."),
        )
    max_archive_bytes = retention_config.max_bytes
    receipts = []
    capture_group_id = uuid.uuid4().hex
    protected_until_ns = (
        time.time_ns()
        + retention_config.min_protected_age_days * 24 * 60 * 60 * 1_000_000_000
    )
    required_bytes = 0
    present = []

    for path in targets:
        try:
            if not os.path.lexists(path):
                parent = _nearest_existing_parent(path)
                before = _identity(os.stat(parent, follow_symlinks=False))
                if os.path.lexists(path):
                    return _plain_failure(path, "The file appeared while its recovery state was checked.")
                after = _identity(os.stat(parent, follow_symlinks=False))
                if before != after:
                    return _plain_failure(path, "Its containing folder changed during verification.")
                tombstone = archive_tx.create_absent_tombstone(
                    store.agw_home(), path, (parent,) + after,
                    reason=f"verified absence before {label}",
                    policy_revision=policy_revision,
                )
                receipts.append(PreimageReceipt(
                    path, "ABSENT", identity=(parent,) + after,
                    transaction_id=tombstone["transaction_id"],
                    policy_revision=policy_revision,
                    recovery_record_kind="absent_tombstone",
                    recovery_record_state=str(tombstone.get("state") or ""),
                ))
                continue

            st = os.stat(path, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                return _plain_failure(path, "Only ordinary local files can be safely backed up here.")
            logical_size = int(st.st_size)
            if max_file_bytes > 0 and logical_size > max_file_bytes:
                limit_mb = max_file_bytes // (1024 * 1024)
                return _plain_failure(
                    path, f"The file is larger than the configured {limit_mb} MB backup limit."
                )
            required_bytes += max(logical_size, allocated_size(path, st))
            present.append((path, _identity(st)))
        except OSError as exc:
            return _plain_failure(path, f"The file could not be read safely ({exc}).")

    try:
        store.maintain_retention(
            policy=retention_config, incoming_bytes=required_bytes,
            lock_context=store.Lock("recovery-store", timeout=30.0),
        )
        if required_bytes:
            capacity_root = _nearest_existing_parent(
                os.path.join(store.agw_home(), "archive", "probe")
            )
            if shutil.disk_usage(capacity_root).free < required_bytes:
                return _plain_failure(
                    present[0][0], "The recovery store does not have enough free disk space."
                )
    except store.ArchiveCapacityError:
        target = present[0][0] if present else (targets[0] if targets else "")
        return _plain_failure(
            target,
            "The recovery store does not have enough configured capacity; "
            "its protected rollback points cannot be pruned safely.",
        )
    except OSError as exc:
        target = present[0][0] if present else (targets[0] if targets else "")
        return _plain_failure(target, f"Recovery-store capacity could not be verified ({exc}).")

    for path, before_identity in present:
        try:
            before_hash = store.file_sha256(path)
            entry = store.archive_file(
                path, mode="copy", dedupe=False,
                reason=f"verified pre-image before {label}", actor="guardrails-hook",
                retention_class="mutation_preimage",
                protected_until_ns=protected_until_ns,
                capture_group_id=capture_group_id,
                retention_config=retention_config,
            )
            artifact = str(entry.get("dest") or "")
            transaction_id = str(entry.get("transaction_id") or "")
            if not artifact or not transaction_id or not os.path.isfile(artifact):
                return _plain_failure(path, "The recovery copy was not retrievable after it was created.")
            record = archive_tx.bind_policy_revision(
                store.agw_home(), transaction_id, policy_revision
            )
            if str(record.get("policy_revision") or "") != policy_revision:
                return _plain_failure(
                    path, "The recovery copy was not bound to the active safety policy."
                )
            artifact_hash = store.file_sha256(artifact)
            after_stat = os.stat(path, follow_symlinks=False)
            after_hash = store.file_sha256(path)
            if artifact_hash != before_hash or after_hash != before_hash \
                    or _identity(after_stat) != before_identity:
                return _plain_failure(path, "The file changed while its recovery copy was being verified.")
            receipts.append(PreimageReceipt(
                path, "PRESENT", artifact=artifact, sha256=before_hash,
                identity=before_identity, transaction_id=transaction_id,
                policy_revision=policy_revision,
                recovery_record_kind="archive",
                recovery_record_state=str(record.get("state") or ""),
            ))
        except (OSError, ValueError, TypeError) as exc:
            return _plain_failure(path, f"The recovery copy could not be completed ({exc}).")
        except Exception:
            return _plain_failure(path, "The recovery store reported an unexpected capture failure.")

    if len(receipts) != len(targets):
        target = targets[len(receipts)] if len(receipts) < len(targets) else ""
        return _plain_failure(target, "Not every target received a recovery receipt.")
    return PreimageResult(True, receipts=receipts)


def receipt_valid(receipt: PreimageReceipt, current_policy_revision: str) -> bool:
    """Return whether a receipt remains authoritative for the active policy."""
    if (not current_policy_revision
            or receipt.policy_revision != current_policy_revision
            or not receipt.transaction_id):
        return False
    try:
        record = archive_tx.load(store.agw_home(), receipt.transaction_id)
    except (OSError, ValueError):
        return False
    if record.get("state") != archive_tx.COMMITTED \
            or record.get("policy_revision") != current_policy_revision \
            or archive_tx.canonical_path(record.get("src", "")) \
            != archive_tx.canonical_path(receipt.target):
        return False
    if receipt.state == "ABSENT":
        return store.absent_tombstone_is_verified(
            record, receipt.target, receipt.identity
        )
    if receipt.state != "PRESENT" or record.get("kind") != "archive" \
            or receipt.sha256 != record.get("sha256") \
            or archive_tx.canonical_path(receipt.artifact) \
            != archive_tx.canonical_path(record.get("dest", "")):
        return False
    return archive_tx.entry_is_verified(
        store.agw_home(), archive_tx.entry_from_record(record), receipt.target
    )
