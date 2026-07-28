"""Archive store + agw CLI behavior: round-trips, undo, concurrency, conflicts."""
import json
import os
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from core import store
from core import profiles
import agw as agw_cli

REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugin")
AGW = os.path.join(REPO, "scripts", "agw", "agw.py")


def run_agw(*args, env=None, check=True):
    e = dict(os.environ)
    if env:
        e.update(env)
    result = subprocess.run([sys.executable, AGW, *args],
                            capture_output=True, text=True, env=e)
    if check and result.returncode != 0:
        raise AssertionError(f"agw {' '.join(args)} failed: {result.stderr}")
    return result


def test_archive_restore_roundtrip(tmp_path):
    f = tmp_path / "report.txt"
    f.write_text("important content")
    entry = store.archive_file(str(f), mode="move", reason="test")
    assert not f.exists()
    assert os.path.exists(entry["dest"])
    store.restore(str(f))
    assert f.read_text() == "important content"


def test_versions_monotonic(tmp_path):
    f = tmp_path / "doc.txt"
    for i in range(3):
        f.write_text(f"version {i}")
        store.archive_file(str(f), mode="copy")
    versions = [e["version"] for e in store.list_versions(str(f))]
    assert versions == [1, 2, 3]


def test_restore_specific_version(tmp_path):
    f = tmp_path / "doc.txt"
    for i in range(3):
        f.write_text(f"version {i}")
        store.archive_file(str(f), mode="copy")
    store.restore(str(f), version=1)
    assert f.read_text() == "version 0"


def test_restore_never_clobbers_silently(tmp_path):
    f = tmp_path / "doc.txt"
    f.write_text("old")
    store.archive_file(str(f), mode="copy")
    f.write_text("newer work")
    store.restore(str(f))
    # the "newer work" must itself have been archived before restore
    contents = [open(e["dest"]).read() for e in store.list_versions(str(f))
                if os.path.isfile(e["dest"])]
    assert "newer work" in contents


def test_undo_archive(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("data")
    store.archive_file(str(f), mode="move")
    assert not f.exists()
    store.undo_last()
    assert f.read_text() == "data"


def test_undo_move(tmp_path):
    src = tmp_path / "a.txt"
    src.write_text("1")
    dest = tmp_path / "sub" / "b.txt"
    store.logged_move(str(src), str(dest))
    assert dest.exists() and not src.exists()
    store.undo_last()
    assert src.exists() and not dest.exists()


def test_pre_image_dedupe(tmp_path):
    f = tmp_path / "doc.txt"
    f.write_text("same content")
    e1 = store.archive_file(str(f), mode="copy", dedupe=True)
    e2 = store.archive_file(str(f), mode="copy", dedupe=True)
    assert e1["version"] == 1
    assert e2.get("deduped") is True


def test_concurrent_archives_no_lost_versions(tmp_path):
    files = []
    for i in range(12):
        f = tmp_path / f"f{i}.txt"
        f.write_text(f"content {i}")
        files.append(str(f))
    errors = []

    def worker(path):
        try:
            store.archive_file(path, mode="move")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(p,)) for p in files]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    ops = [o for o in store.oplog_read() if o.get("op") == "archive"]
    assert len(ops) == 12


def test_path_with_spaces_and_unicode(tmp_path):
    f = tmp_path / "Q3 report — final (v2).txt"
    f.write_text("data")
    store.archive_file(str(f), mode="move")
    store.restore(str(f))
    assert f.read_text() == "data"


# --- CLI-level tests ----------------------------------------------------------

def test_cli_checkout_publish_roundtrip(tmp_path, agw_home):
    f = tmp_path / "notes.txt"
    f.write_text("original text")
    run_agw("checkout", str(f))
    working = tmp_path / "_workspace" / "notes.txt"
    assert working.read_text() == "original text"
    working.write_text("edited text")
    run_agw("publish", str(f))
    assert f.read_text() == "edited text"
    # prior version archived
    assert any(e["op"] == "archive" for e in store.oplog_read())
    run_agw("restore", str(f))
    assert f.read_text() == "original text"


def test_cli_publish_conflict_detection(tmp_path, agw_home):
    f = tmp_path / "doc.txt"
    f.write_text("base")
    run_agw("checkout", str(f))
    f.write_text("someone else edited this")  # simulate external edit
    (tmp_path / "_workspace" / "doc.txt").write_text("agent edit")
    result = run_agw("publish", str(f), check=False)
    assert result.returncode == 3
    assert "CONFLICT" in result.stderr
    assert f.read_text() == "someone else edited this"  # live file untouched


def test_cli_scan_reports_stubs(tmp_path, agw_home):
    (tmp_path / "Budget.gsheet").write_text(json.dumps({"url": "x"}))
    (tmp_path / "real.txt").write_text("hello")
    result = run_agw("scan", str(tmp_path), "--json")
    data = json.loads(result.stdout)
    assert "Budget.gsheet" in data["gdoc_stubs"]
    assert data["files"] == 2
    assert data["complete"] is True


def test_cli_scan_rejects_file_path(tmp_path, agw_home):
    target = tmp_path / "not-a-directory.txt"
    target.write_text("content")
    result = run_agw("scan", str(target), "--json", check=False)
    assert result.returncode == 2
    assert "requires a directory" in result.stderr


def test_cli_scan_bounds_return_partial_results(tmp_path, agw_home):
    for index in range(8):
        (tmp_path / f"item-{index}.txt").write_text(str(index))
    result = run_agw(
        "scan", str(tmp_path), "--max-files", "3", "--no-size", "--json"
    )
    data = json.loads(result.stdout)
    assert data["complete"] is False
    assert data["stop_reason"] == "max_files"
    assert data["files_inspected"] == 3
    assert data["bytes"] is None
    assert data["elapsed_seconds"] >= 0


def test_sync_profile_precedes_enclosing_git_marker(tmp_path):
    sync_root = tmp_path / "shared"
    sync_root.mkdir()
    (sync_root / ".dropbox").mkdir()
    repo = sync_root / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    profiles._cache.clear()
    assert profiles.detect(str(repo)).name == "dropbox"


def test_scan_placeholder_checks_use_metadata_without_opening_content(
        tmp_path, monkeypatch, capsys):
    folder = tmp_path / "OneDrive - Example"
    folder.mkdir()
    target = folder / "cloud.dat"
    target.write_bytes(b"metadata-only")
    original = profiles.is_placeholder
    observed = []

    def inspect(path, *, st=None, profile=None):
        observed.append((path, st is not None, profile.name))
        return original(path, st=st, profile=profile)

    monkeypatch.setattr(profiles, "is_placeholder", inspect)
    monkeypatch.setattr("builtins.open", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("scan opened file content")
    ))
    agw_cli.cmd_scan(SimpleNamespace(
        path=str(folder), fast=False, max_seconds=5.0, max_files=10,
        max_depth=2, no_size=True, json=True,
    ))
    data = json.loads(capsys.readouterr().out)
    assert data["files_inspected"] == 1
    assert observed == [(str(target), True, "onedrive-sharepoint")]


def test_cli_snapshot_preflight(tmp_path, agw_home):
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 1000)
    result = run_agw("snapshot", str(tmp_path), check=False,
                     env={"AGW_SNAPSHOT_MAX_BYTES": "100"})
    assert result.returncode == 3
    assert "force" in result.stderr.lower()
    # and --force overrides
    result = run_agw("snapshot", str(tmp_path), "--force",
                     env={"AGW_SNAPSHOT_MAX_BYTES": "100"})
    assert result.returncode == 0


def test_cli_prune_refuses_without_human_flag(agw_home):
    result = run_agw("prune", check=False)
    assert result.returncode == 4
    assert "human" in result.stderr.lower() or "refusing" in result.stderr.lower()


def test_cli_doctor_runs(agw_home):
    result = run_agw("doctor", "--json")
    data = json.loads(result.stdout)
    assert data["agw_home_writable"] is True


def test_cli_doctor_uses_real_archive_write_probe(tmp_path):
    blocked_home = tmp_path / "blocked-home"
    blocked_home.mkdir()
    (blocked_home / "archive").write_text("not a directory")
    result = run_agw("doctor", "--json", env={"AGW_HOME": str(blocked_home)})
    data = json.loads(result.stdout)
    assert data["agw_home_writable"] is False


def test_cli_archive_permission_failure_is_plain_and_preserves_source(tmp_path):
    blocked_home = tmp_path / "blocked-home"
    blocked_home.mkdir()
    (blocked_home / "archive").write_text("not a directory")
    source = tmp_path / "keep-me.txt"
    source.write_text("still here")

    result = run_agw(
        "archive", str(source), check=False, env={"AGW_HOME": str(blocked_home)}
    )

    assert result.returncode != 0
    assert source.read_text() == "still here"
    assert "original file was not moved or changed" in result.stderr.lower()
    assert "host's normal approval" in result.stderr.lower()
    assert "traceback" not in result.stderr.lower()
    assert str(blocked_home).lower() not in result.stderr.lower()
