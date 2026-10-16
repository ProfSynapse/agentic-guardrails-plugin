"""Media choices must preserve bytes independently of conversational consent."""
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from core import archive_transactions as archive_tx
from core import engine, media_review as review, preimages, store
import file_ops
import media_ops

PLUGIN = Path(__file__).resolve().parents[1] / "plugin"


def original(tmp_path, name="recording.mp4"):
    path = tmp_path / name
    path.write_bytes(b"irreplaceable original")
    return path


def prepared(tmp_path, **kwargs):
    target = original(tmp_path)
    plan = media_ops.prepare(str(target), **kwargs)
    return target, plan


def finish_stage(plan, content=b"finished replacement"):
    Path(plan["staged_path"]).write_bytes(content)


def cli(*args):
    return subprocess.run([sys.executable, str(PLUGIN / "scripts/agw/agw.py"),
                           *args, "--json"], capture_output=True, text=True, timeout=30)


@pytest.mark.parametrize("name", ["recording.MP4", "audio.wav", "photo.png"])
def test_first_attempt_stops_without_copying_media(tmp_path, monkeypatch, name):
    target = original(tmp_path, name)
    def no_hash(*args, **kwargs):
        raise AssertionError("hook must not read media bytes")
    monkeypatch.setattr(store, "file_sha256", no_hash)
    result = preimages.prepare([str(target)], "write", 1,
                              policy_revision="current", require_media_review=True)
    assert not result.ok
    assert result.error_code == "media_review_required"
    assert result.details["approval_verified"] is False
    assert result.details["choices"] == ["replace", "save-separately", "cancel"]
    assert target.read_bytes() == b"irreplaceable original"
    assert not (Path(store.agw_home()) / "archive").exists()
    repeated = preimages.prepare([str(target)], "write", 1,
                                policy_revision="current", require_media_review=True)
    assert repeated.details["id"] == result.details["id"]


def test_documents_and_new_media_keep_normal_recovery(tmp_path):
    document = original(tmp_path, "signed.pdf")
    new_media = tmp_path / "new.mp4"
    result = preimages.prepare([str(document), str(new_media)], "write", 1000,
                              policy_revision="current", require_media_review=True)
    assert result.ok
    assert [r.state for r in result.receipts] == ["ABSENT", "PRESENT"]


def test_replace_preserves_exact_original_and_consumes_operation(tmp_path):
    target, plan = prepared(tmp_path)
    finish_stage(plan)
    result = media_ops.continue_operation(plan["id"], "replace")
    assert result["state"] == "completed"
    assert target.read_bytes() == b"finished replacement"
    assert not Path(plan["staged_path"]).exists()
    store.restore(str(target))
    assert target.read_bytes() == b"irreplaceable original"
    with pytest.raises(review.MediaReviewError, match="already used"):
        media_ops.continue_operation(plan["id"], "replace")


def test_save_separately_transfers_owned_stage_without_copying_bytes(tmp_path, monkeypatch):
    target, plan = prepared(tmp_path)
    finish_stage(plan)
    stage_inode = os.stat(plan["staged_path"]).st_ino
    def no_copy(*args, **kwargs):
        raise AssertionError("owned stage should be promoted without copying")
    monkeypatch.setattr(media_ops.shutil, "copyfileobj", no_copy)
    result = media_ops.continue_operation(plan["id"], "save-separately")
    assert Path(result["path"]).read_bytes() == b"finished replacement"
    assert os.stat(result["path"]).st_ino == stage_inode
    assert target.read_bytes() == b"irreplaceable original"
    assert not Path(plan["staged_path"]).exists()
    assert not (Path(store.agw_home()) / "archive").exists()


def test_separate_collision_never_overwrites_and_consumes_attempt(tmp_path):
    target, plan = prepared(tmp_path)
    finish_stage(plan)
    separate = Path(plan["separate_path"])
    separate.write_bytes(b"someone else's output")
    with pytest.raises(review.MediaReviewError, match="consumed"):
        media_ops.continue_operation(plan["id"], "save-separately")
    assert separate.read_bytes() == b"someone else's output"
    assert target.read_bytes() == b"irreplaceable original"
    assert Path(plan["staged_path"]).exists()
    assert review.read(plan["id"])["state"] == "needs-inspection"


def test_cancel_changes_no_files_even_with_stage_or_changed_original(tmp_path):
    target, plan = prepared(tmp_path)
    finish_stage(plan)
    target.write_bytes(b"external edit")
    result = media_ops.continue_operation(plan["id"], "cancel")
    assert result["changed"] == 0
    assert target.read_bytes() == b"external edit"
    assert Path(plan["staged_path"]).read_bytes() == b"finished replacement"
    assert not Path(plan["separate_path"]).exists()
    with pytest.raises(review.MediaReviewError, match="already used"):
        media_ops.continue_operation(plan["id"], "save-separately")


@pytest.mark.parametrize("action", ["replace", "save-separately", "archive"])
def test_changed_original_invalidates_continuation(tmp_path, action):
    target, plan = prepared(tmp_path, operation="archive" if action == "archive" else "replace")
    finish_stage(plan)
    target.write_bytes(b"other person's edit")
    with pytest.raises(review.MediaReviewError, match="Original media changed"):
        media_ops.continue_operation(plan["id"], action)
    assert target.read_bytes() == b"other person's edit"


def test_expiry_and_policy_change_block_execution(tmp_path, monkeypatch):
    target, plan = prepared(tmp_path)
    finish_stage(plan)
    with monkeypatch.context() as scoped:
        scoped.setattr(media_ops.time, "time", lambda: plan["expires_at"] + 1)
        with pytest.raises(review.MediaReviewError, match="expired"):
            media_ops.continue_operation(plan["id"], "replace")
    record = review.read(plan["id"])
    record["plan"]["policy_revision"] = "old"
    record["plan_sha256"] = review._digest(record["plan"])
    review.write(record)
    with pytest.raises(review.MediaReviewError, match="Policy changed"):
        media_ops.continue_operation(plan["id"], "replace")
    assert target.read_bytes() == b"irreplaceable original"


def test_tampered_record_and_traversal_are_rejected(tmp_path):
    target, plan = prepared(tmp_path)
    record = review.read(plan["id"])
    record["plan"]["target"] = str(tmp_path / "other.mp4")
    review.write(record)
    with pytest.raises(review.MediaReviewError, match="integrity"):
        media_ops.continue_operation(plan["id"], "cancel")
    with pytest.raises(review.MediaReviewError, match="Invalid media operation ID"):
        media_ops.continue_operation("../../other", "cancel")


def test_archive_is_recoverable_and_does_not_offer_replacement(tmp_path):
    target, plan = prepared(tmp_path, operation="archive")
    assert plan["choices"] == ["archive", "cancel"]
    with pytest.raises(review.MediaReviewError, match="does not match"):
        media_ops.continue_operation(plan["id"], "replace")
    result = media_ops.continue_operation(plan["id"], "archive")
    assert not target.exists()
    assert Path(result["archive"]["dest"]).read_bytes() == b"irreplaceable original"
    store.restore(str(target))
    assert target.read_bytes() == b"irreplaceable original"


def test_capacity_never_downgrades_to_permanent_replacement(tmp_path, monkeypatch):
    target, plan = prepared(tmp_path)
    finish_stage(plan)
    monkeypatch.setenv("AGW_ARCHIVE_MEDIA_MAX_BYTES", "0")
    with pytest.raises(review.MediaReviewError):
        media_ops.continue_operation(plan["id"], "replace")
    assert target.read_bytes() == b"irreplaceable original"
    assert Path(plan["staged_path"]).read_bytes() == b"finished replacement"


def test_native_capture_limit_does_not_limit_explicit_cli_capture(tmp_path, monkeypatch):
    target, plan = prepared(tmp_path)
    finish_stage(plan)
    monkeypatch.setenv("AGW_PRESNAP_MAX_BYTES", "1")
    assert media_ops.continue_operation(plan["id"], "replace")["state"] == "completed"
    store.restore(str(target))
    assert target.read_bytes() == b"irreplaceable original"


def test_external_supplied_stage_is_copied_independently_and_not_consumed(tmp_path):
    external = tmp_path / "build"
    external.mkdir()
    stage = external / "finished.mp4"
    stage.write_bytes(b"finished replacement")
    target, plan = prepared(tmp_path, staged=str(stage))
    result = media_ops.continue_operation(plan["id"], "save-separately")
    assert stage.read_bytes() == b"finished replacement"
    assert not os.path.samefile(stage, result["path"])
    stage.write_bytes(b"later edit")
    assert Path(result["path"]).read_bytes() == b"finished replacement"


def test_keep_both_reuses_finished_file_beside_original_without_copy(tmp_path, monkeypatch):
    stage = tmp_path / "finished.mp4"
    stage.write_bytes(b"finished replacement")
    target, plan = prepared(tmp_path, staged=str(stage))
    before = {p.name: (p.stat().st_ino, p.read_bytes()) for p in (target, stage)}
    assert plan["separate_result"] == {"path": str(stage), "reuses_existing_file": True}
    def no_copy(*args, **kwargs):
        raise AssertionError("keeping existing files must not copy bytes")
    monkeypatch.setattr(media_ops.shutil, "copyfileobj", no_copy)
    result = media_ops.continue_operation(plan["id"], "save-separately")
    assert result["changed"] == 0 and result["reused_existing_file"]
    assert result["path"] == str(stage)
    assert {p.name: (p.stat().st_ino, p.read_bytes()) for p in tmp_path.glob("*.mp4")} == before
    assert not os.path.samefile(target, stage)
    assert not (Path(store.agw_home()) / "archive").exists()
    assert review.describe(review.read(plan["id"]))["choices"] == []


def capacity_fixture(tmp_path, monkeypatch, *, supplied=True, operation="replace"):
    for name, value in {"MAX_BYTES": 1_000_000, "DOCUMENT_RESERVE_BYTES": 500_000,
                        "MEDIA_MAX_BYTES": 375_000, "DERIVED_MAX_BYTES": 125_000}.items():
        monkeypatch.setenv("AGW_ARCHIVE_" + name, str(value))
    retained = tmp_path / "retained.wav"
    retained.write_bytes(b"r" * 330_000)
    entry = store.archive_file(
        str(retained), mode="copy", retention_class="safety_archive",
        retention_config=media_ops.retention_config.load(),
    )
    target = tmp_path / "original.mp4"
    target.write_bytes(b"o" * 100_000)
    stage = tmp_path / "finished.mp4"
    if supplied and operation == "replace":
        stage.write_bytes(b"finished replacement")
    plan = media_ops.prepare(str(target), operation=operation,
                             staged=str(stage) if supplied and operation == "replace" else "")
    if not supplied and operation == "replace":
        finish_stage(plan)
    return target, plan, Path(entry["dest"])


@pytest.mark.parametrize("supplied,action", [(True, "save-separately"),
                                          (False, "save-separately"), (True, "cancel")])
def test_full_capacity_offers_same_operation_preserving_continuation(
    tmp_path, monkeypatch, supplied, action,
):
    target, plan, retained = capacity_fixture(tmp_path, monkeypatch, supplied=supplied)
    with pytest.raises(review.MediaCapacityBlocked) as failure:
        media_ops.continue_operation(plan["id"], "replace")
    details = failure.value.details
    assert details["state"] == "capacity-blocked"
    assert details["target_mutation_started"] is False
    assert details["choices"] == ["save-separately", "cancel"]
    assert details["capacity"]["storage_budget"] == "media"
    assert "remediation" not in details["capacity"]
    assert "policy" not in details["capacity"]
    assert "remediation" in review.read(plan["id"])["failure_details"]
    assert details["continue_argv"][action][3] == plan["id"]
    assert target.read_bytes() == b"o" * 100_000
    assert retained.read_bytes() == b"r" * 330_000
    # Replacement cannot retry under the restricted state, even if requested.
    with pytest.raises(review.MediaCapacityBlocked):
        media_ops.continue_operation(plan["id"], "replace")
    result = json.loads(cli("media", "continue", plan["id"], "--action", action).stdout)
    assert result["state"] == ("cancelled" if action == "cancel" else "completed")
    if action == "save-separately":
        assert Path(result["path"]).read_bytes() == b"finished replacement"
        assert result["changed"] == (0 if supplied else 1)
    assert target.read_bytes() == b"o" * 100_000
    assert retained.read_bytes() == b"r" * 330_000
    with pytest.raises(review.MediaReviewError, match="already used"):
        media_ops.continue_operation(plan["id"], action)


def test_capacity_blocked_archive_offers_only_cancel(tmp_path, monkeypatch):
    target, plan, retained = capacity_fixture(tmp_path, monkeypatch, operation="archive")
    with pytest.raises(review.MediaCapacityBlocked) as failure:
        media_ops.continue_operation(plan["id"], "archive")
    assert failure.value.details["choices"] == ["cancel"]
    assert target.read_bytes() == b"o" * 100_000
    assert media_ops.continue_operation(plan["id"], "cancel")["changed"] == 0
    assert retained.exists()


@pytest.mark.parametrize("changed", ["target", "stage", "policy", "expiry"])
def test_capacity_continuation_revalidates_original_stage_policy_and_expiry(
    tmp_path, monkeypatch, changed,
):
    target, plan, _ = capacity_fixture(tmp_path, monkeypatch, supplied=False)
    with pytest.raises(review.MediaCapacityBlocked):
        media_ops.continue_operation(plan["id"], "replace")
    if changed == "target":
        target.write_bytes(b"external edit")
    elif changed == "stage":
        Path(plan["staged_path"]).write_bytes(b"different replacement")
    elif changed == "policy":
        monkeypatch.setattr(media_ops.engine, "load_policy", lambda _: type("Policy", (), {"revision": "changed"})())
    else:
        monkeypatch.setattr(media_ops.time, "time", lambda: plan["expires_at"] + 1)
    with pytest.raises(review.MediaReviewError):
        media_ops.continue_operation(plan["id"], "save-separately")
    assert not Path(plan["separate_path"]).exists()
    assert target.read_bytes() == (b"external edit" if changed == "target" else b"o" * 100_000)


def test_error_code_alone_never_enables_capacity_continuation(tmp_path, monkeypatch):
    target, plan = prepared(tmp_path)
    finish_stage(plan)
    def ambiguous(*args, **kwargs):
        error = file_ops.FileOperationError("unclassified failure")
        error.error_code = "archive_capacity_exceeded"
        raise error
    monkeypatch.setattr(media_ops.publication, "publish_staged_batch", ambiguous)
    with pytest.raises(review.MediaReviewError, match="consumed"):
        media_ops.continue_operation(plan["id"], "replace")
    assert review.read(plan["id"])["state"] == "needs-inspection"
    assert review.describe(review.read(plan["id"]))["choices"] == []
    with pytest.raises(review.MediaReviewError, match="already used"):
        media_ops.continue_operation(plan["id"], "save-separately")
    assert target.read_bytes() == b"irreplaceable original"


def test_failure_after_publication_never_offers_capacity_shortcut(tmp_path, monkeypatch):
    target, plan = prepared(tmp_path)
    finish_stage(plan)
    terminal = media_ops.publication._terminal_record
    def fail_after_commit(*args, **kwargs):
        terminal(*args, **kwargs)
        raise store.ArchiveCapacityError("late failure with capacity code", {})
    monkeypatch.setattr(media_ops.publication, "_terminal_record", fail_after_commit)
    with pytest.raises(review.MediaReviewError, match="consumed"):
        media_ops.continue_operation(plan["id"], "replace")
    assert review.read(plan["id"])["state"] == "needs-inspection"
    assert target.read_bytes() == b"finished replacement"
    assert any(Path(v["dest"]).read_bytes() == b"irreplaceable original"
               for v in store.list_versions(str(target)))
    with pytest.raises(review.MediaReviewError, match="already used"):
        media_ops.continue_operation(plan["id"], "save-separately")


@pytest.mark.parametrize("boundary", ["candidate", "backup", "publication"])
def test_disk_full_preserves_media_and_requires_inspection(tmp_path, monkeypatch, boundary):
    """OS write failures are not the proven budget-refusal continuation path."""
    target, plan = prepared(tmp_path)
    finish_stage(plan)
    stage = Path(plan["staged_path"])
    failed_destinations = []

    def partial_copy(source, destination, *args, **kwargs):
        Path(destination).write_bytes(b"partial")
        failed_destinations.append(Path(destination))
        raise OSError(errno.ENOSPC, "No space left on device")

    def failed_publish(*args, **kwargs):
        raise OSError(errno.ENOSPC, "No space left on device")

    with monkeypatch.context() as patch:
        if boundary == "candidate":
            patch.setattr(media_ops.publication.shutil, "copy2", partial_copy)
        elif boundary == "backup":
            patch.setattr(archive_tx, "_copy_file_hashed", partial_copy)
        else:
            patch.setattr(file_ops, "replace_with_retry", failed_publish)
        with pytest.raises(review.MediaReviewError, match="consumed") as failure:
            media_ops.continue_operation(plan["id"], "replace")

    assert "No space left" in str(failure.value) or "No space left" in str(failure.value.details)
    assert target.read_bytes() == b"irreplaceable original"
    assert stage.read_bytes() == b"finished replacement"
    assert not list(tmp_path.glob(".agw-publish-*"))
    record = review.read(plan["id"])
    assert record["state"] == "needs-inspection"
    assert review.describe(record)["choices"] == []
    with pytest.raises(review.MediaReviewError, match="already used"):
        media_ops.continue_operation(plan["id"], "save-separately")

    if boundary == "candidate":
        assert failed_destinations and not any(p.exists() for p in failed_destinations)
        assert not store.list_versions(str(target))
    elif boundary == "backup":
        records = [item["record"] for item in store.discover_archive_transactions()
                   if item.get("record") and item["record"].get("src") == str(target)]
        assert len(records) == 1 and records[0]["state"] == archive_tx.PREPARING
        assert not Path(records[0]["dest"]).exists()
        recovered = archive_tx.recover_record(store.agw_home(), records[0])
        assert Path(recovered["quarantine"]).read_bytes() == b"partial"
        assert not any(p.exists() for p in failed_destinations)
        assert target.read_bytes() == b"irreplaceable original"
    else:
        assert any(Path(v["dest"]).read_bytes() == b"irreplaceable original"
                   for v in store.list_versions(str(target)))


def test_concurrent_capacity_alternatives_claim_only_once(tmp_path, monkeypatch):
    _, plan, _ = capacity_fixture(tmp_path, monkeypatch, supplied=False)
    with pytest.raises(review.MediaCapacityBlocked):
        media_ops.continue_operation(plan["id"], "replace")
    barrier = Barrier(2)
    def run():
        barrier.wait(timeout=5)
        try:
            return media_ops.continue_operation(plan["id"], "save-separately")["state"]
        except review.MediaReviewError as exc:
            assert "already used" in str(exc)
            return "refused"
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: run(), range(2))) == ["completed", "refused"]
    assert Path(plan["separate_path"]).read_bytes() == b"finished replacement"


@pytest.mark.parametrize("action", ["replace", "save-separately"])
def test_changed_supplied_stage_cannot_continue(tmp_path, action):
    stage = tmp_path / "finished.mp4"
    stage.write_bytes(b"first")
    target, plan = prepared(tmp_path, staged=str(stage))
    stage.write_bytes(b"second")
    with pytest.raises(review.MediaReviewError, match="Replacement changed"):
        media_ops.continue_operation(plan["id"], action)
    assert target.read_bytes() == b"irreplaceable original"


def test_symlink_and_hardlink_substitution_refused(tmp_path):
    target, plan = prepared(tmp_path)
    os.link(target, plan["staged_path"])
    with pytest.raises(review.MediaReviewError, match="Original media changed|independent"):
        media_ops.continue_operation(plan["id"], "replace")
    os.unlink(plan["staged_path"])
    # Linking changes the original's ctime. Prepare the new identity.
    plan = media_ops.prepare(str(target))
    os.symlink(target, plan["staged_path"])
    with pytest.raises(review.MediaReviewError, match="ordinary"):
        media_ops.continue_operation(plan["id"], "save-separately")


def test_parent_substitution_refused(tmp_path):
    folder = tmp_path / "folder"
    folder.mkdir()
    target, plan = prepared(folder)
    finish_stage(plan)
    folder.rename(tmp_path / "moved")
    folder.mkdir()
    original(folder)
    with pytest.raises(review.MediaReviewError, match="Original media changed"):
        media_ops.continue_operation(plan["id"], "replace")


def test_metadata_cleanup_never_removes_stages(tmp_path, monkeypatch):
    target, plan = prepared(tmp_path)
    finish_stage(plan)
    monkeypatch.setattr(review.time, "time", lambda: plan["expires_at"] + 1)
    newer = media_ops.prepare(str(target))
    assert newer["id"] != plan["id"]
    assert not Path(review._path(plan["id"])).exists()
    assert Path(plan["staged_path"]).exists()


@pytest.mark.parametrize("host,tool,tool_input", [
    ("claude", "Write", lambda path: {"file_path": str(path), "content": "replacement"}),
    ("codex", "apply_patch", lambda path: {"input": "*** Begin Patch\n*** Update File: " + str(path) + "\n@@\n-old\n+new\n*** End Patch\n"}),
])
def test_real_hooks_return_conversational_refusal(tmp_path, host, tool, tool_input):
    target = original(tmp_path)
    payload = {"tool_name": tool, "tool_input": tool_input(target),
               "hook_event_name": "PreToolUse", "cwd": str(tmp_path), "session_id": "media-test"}
    env = dict(os.environ, PLUGIN_ROOT=str(PLUGIN), CLAUDE_PLUGIN_ROOT=str(PLUGIN),
               AGW_TEST_MODE="1", AGW_APPROVAL_PROVIDER="headless")
    result = subprocess.run([sys.executable, str(PLUGIN / "scripts" / host / "pretooluse.py")],
                            input=json.dumps(payload), text=True, capture_output=True, env=env, timeout=30)
    out = json.loads(result.stdout)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "clarify-media-operation" in reason
    assert "save-separately" in reason
    assert target.read_bytes() == b"irreplaceable original"


def test_cli_archive_stops_then_can_resume(tmp_path):
    target = original(tmp_path)
    stopped = cli("archive", str(target))
    assert stopped.returncode != 0
    error = json.loads(stopped.stderr)["error"]
    assert error["code"] == "media_review_required"
    plan = error["details"]
    resumed = cli("media", "continue", plan["id"], "--action", "archive")
    assert resumed.returncode == 0, resumed.stderr
    assert not target.exists()


def test_cli_publish_cannot_skip_media_review(tmp_path):
    target = original(tmp_path)
    stage = tmp_path / "finished.mp4"
    stage.write_bytes(b"replacement")
    result = cli("publish-file", "--target", str(target), "--staged", str(stage))
    assert result.returncode != 0
    assert json.loads(result.stderr)["error"]["code"] == "media_review_required"
    assert target.read_bytes() == b"irreplaceable original"
    assert stage.read_bytes() == b"replacement"
    pending = json.loads(result.stderr)["error"]["details"]
    assert pending["supplied_stage"] == str(stage)
    resumed = cli("media", "continue", pending["id"], "--action", "replace")
    assert resumed.returncode == 0, resumed.stderr
    assert target.read_bytes() == b"replacement"
    assert stage.read_bytes() == b"replacement"


def test_unknown_destructive_action_has_no_escape_hatch(tmp_path):
    target, plan = prepared(tmp_path)
    result = cli("media", "continue", plan["id"], "--action", "replace-permanently")
    assert result.returncode != 0
    assert target.read_bytes() == b"irreplaceable original"


@pytest.mark.skipif(os.name == "nt", reason="Windows truncate does not guarantee sparse allocation")
def test_twenty_gib_original_is_not_hashed_or_copied_when_it_cannot_fit(tmp_path, monkeypatch):
    target = tmp_path / "huge.mp4"
    with target.open("wb") as handle:
        handle.truncate(20 * 1024 ** 3)  # Sparse fixture, not a 20 GiB allocation.
    def no_hash(*args, **kwargs):
        raise AssertionError("oversized original must be refused without reading its bytes")
    monkeypatch.setattr(store, "file_sha256", no_hash)
    plan = media_ops.prepare(str(target))
    with pytest.raises(review.MediaCapacityBlocked):
        media_ops.continue_operation(plan["id"], "replace")
    assert review.read(plan["id"])["state"] == "capacity-blocked"
    assert not (Path(store.agw_home()) / "archive").exists()
    assert media_ops.continue_operation(plan["id"], "cancel")["changed"] == 0


def test_crash_after_claim_cannot_replay(tmp_path, monkeypatch):
    target, plan = prepared(tmp_path)
    finish_stage(plan)
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt("process interruption")
    monkeypatch.setattr(media_ops, "_save_separately", interrupted)
    with pytest.raises(KeyboardInterrupt):
        media_ops.continue_operation(plan["id"], "save-separately")
    assert review.read(plan["id"])["state"] == "claimed"
    with pytest.raises(review.MediaReviewError, match="already used"):
        media_ops.continue_operation(plan["id"], "save-separately")
    assert target.read_bytes() == b"irreplaceable original"


@pytest.mark.parametrize("exit_after_publication", [False, True])
def test_process_exit_retains_claim_and_prevents_duplicate_publication(
    tmp_path, exit_after_publication,
):
    target, plan = prepared(tmp_path)
    finish_stage(plan)
    # Exit without unwinding Python context managers, on either side of the
    # filesystem effect but before the completed operation record is written.
    script = """
import os, sys
sys.path.insert(0, sys.argv[1])
sys.path.insert(0, sys.argv[2])
import media_ops
publish = media_ops._save_separately
def interrupted(*args, **kwargs):
    if sys.argv[4] == 'published':
        publish(*args, **kwargs)
    os._exit(73)
media_ops._save_separately = interrupted
media_ops.continue_operation(sys.argv[3], 'save-separately')
"""
    crashed = subprocess.run(
        [sys.executable, "-c", script, str(PLUGIN / "scripts"),
         str(PLUGIN / "scripts/agw"), plan["id"],
         "published" if exit_after_publication else "claimed"],
        capture_output=True, text=True, timeout=30,
    )
    assert crashed.returncode == 73, crashed.stderr
    assert review.read(plan["id"])["state"] == "claimed"
    assert target.read_bytes() == b"irreplaceable original"
    output = Path(plan["separate_path"])
    stage = Path(plan["staged_path"])
    if exit_after_publication:
        assert output.read_bytes() == b"finished replacement"
        assert not stage.exists()
    else:
        assert not output.exists()
        assert stage.read_bytes() == b"finished replacement"
    # A new process must acquire the abandoned lock and refuse replay. A hung
    # lock or a second publication is a failure, even if bytes look correct.
    retry = cli("media", "continue", plan["id"], "--action", "save-separately")
    assert retry.returncode != 0
    failure = json.loads(retry.stderr)["error"]
    assert failure["code"] == "media_operation_blocked"
    assert "already used" in failure["message"]
    assert target.read_bytes() == b"irreplaceable original"
    assert output.exists() is exit_after_publication
    assert review.read(plan["id"])["state"] == "claimed"


def test_metadata_limit_and_expiration_are_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(review, "MAX_RECORDS", 2)
    first = media_ops.prepare(str(original(tmp_path, "one.mp4")))
    media_ops.prepare(str(original(tmp_path, "two.mp4")))
    third = original(tmp_path, "three.mp4")
    with pytest.raises(review.MediaReviewError, match="metadata limit"):
        media_ops.prepare(str(third))
    monkeypatch.setattr(review.time, "time", lambda: first["expires_at"] + 10)
    assert media_ops.prepare(str(third))["state"] == "pending"
    assert len(list(Path(review._root()).glob("*.json"))) == 1


def test_concurrent_continuations_execute_only_once(tmp_path):
    target, plan = prepared(tmp_path)
    finish_stage(plan)
    barrier = Barrier(2)
    def run():
        barrier.wait(timeout=5)
        try:
            return media_ops.continue_operation(plan["id"], "save-separately")["state"]
        except review.MediaReviewError as exc:
            assert "already used" in str(exc)
            return "refused"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run(), range(2)))
    assert sorted(results) == ["completed", "refused"]
    assert target.read_bytes() == b"irreplaceable original"


def test_completed_metadata_retires_automatically_at_capacity(tmp_path, monkeypatch):
    monkeypatch.setattr(review, "MAX_RECORDS", 1)
    target, plan = prepared(tmp_path)
    media_ops.continue_operation(plan["id"], "cancel")
    next_plan = media_ops.prepare(str(target))
    assert next_plan["id"] != plan["id"]
    assert not Path(review._path(plan["id"])).exists()
    assert target.read_bytes() == b"irreplaceable original"


def test_publication_does_not_hold_the_metadata_index_lock(tmp_path, monkeypatch):
    target, plan = prepared(tmp_path)
    finish_stage(plan)
    publish = media_ops.publication.publish_staged_batch
    def checked(*args, **kwargs):
        # A concurrent ordinary publisher holds file locks while preparing a
        # media review. Holding this lock across publication would invert order.
        with store.Lock("media-operations", timeout=0.01):
            pass
        return publish(*args, **kwargs)
    monkeypatch.setattr(media_ops.publication, "publish_staged_batch", checked)
    assert media_ops.continue_operation(plan["id"], "replace")["state"] == "completed"


def test_full_protected_budget_preserves_original_and_staged_output(tmp_path, monkeypatch):
    from core import retention_policy
    for key, value in {"AGW_ARCHIVE_MAX_BYTES": "1000000",
                       "AGW_ARCHIVE_DOCUMENT_RESERVE_BYTES": "500000",
                       "AGW_ARCHIVE_MEDIA_MAX_BYTES": "375000",
                       "AGW_ARCHIVE_DERIVED_MAX_BYTES": "125000"}.items():
        monkeypatch.setenv(key, value)
    retained = tmp_path / "retained.mp4"
    retained.write_bytes(b"r" * 375000)
    store.archive_file(str(retained), mode="copy", retention_class="safety_archive",
                       retention_config=retention_policy.resolve_retention_policy({}, os.environ))
    target, plan = prepared(tmp_path)
    finish_stage(plan)
    with pytest.raises(review.MediaReviewError):
        media_ops.continue_operation(plan["id"], "replace")
    assert target.read_bytes() == b"irreplaceable original"
    assert Path(plan["staged_path"]).read_bytes() == b"finished replacement"


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_continuation_cli_is_a_supported_new_hook_operation(tmp_path, host):
    _, plan = prepared(tmp_path)
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "agw media continue " + plan["id"] + " --action cancel --json"},
        "hook_event_name": "PreToolUse", "cwd": str(tmp_path), "session_id": "media-cli"}
    env = dict(os.environ, PLUGIN_ROOT=str(PLUGIN), CLAUDE_PLUGIN_ROOT=str(PLUGIN),
               AGW_TEST_MODE="1", AGW_APPROVAL_PROVIDER="headless")
    result = subprocess.run([sys.executable, str(PLUGIN / "scripts" / host / "pretooluse.py")],
                            input=json.dumps(payload), text=True, capture_output=True, env=env, timeout=30)
    out = json.loads(result.stdout)
    assert out.get("hookSpecificOutput", {}).get("permissionDecision") == "allow", out
    assert review.read(plan["id"])["state"] == "pending"  # Hook never executes it.
