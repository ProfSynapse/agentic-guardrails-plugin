"""Guarded text construction and declared-output execution."""
import json
import errno
import os
from pathlib import Path
import subprocess
import sys

import pytest

REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugin")
AGW = os.path.join(REPO, "scripts", "agw", "agw.py")
sys.path.insert(0, os.path.join(REPO, "scripts", "agw"))

import file_ops  # noqa: E402
from core import store  # noqa: E402


def run_agw(*args, env=None, check=True, input_text=None):
    process_env = dict(os.environ)
    if env:
        process_env.update(env)
    result = subprocess.run(
        [sys.executable, AGW, *args], capture_output=True, text=True,
        encoding="utf-8", env=process_env, input=input_text,
    )
    if check and result.returncode:
        raise AssertionError(result.stderr)
    return result


def test_atomic_write_snapshots_and_verifies_existing_file(tmp_path):
    target = tmp_path / "app.js"
    target.write_text("old\n", encoding="utf-8")
    before = store.file_sha256(str(target))
    result = file_ops.write_text(
        str(target), "new\n", expected_hash=before, operation="write",
    )
    assert target.read_text(encoding="utf-8") == "new\n"
    assert result["before_hash"] == before
    assert result["after_hash"] == store.file_sha256(str(target))
    assert result["snapshot_state"] == "PRESENT"
    versions = store.list_versions(str(target))
    assert len(versions) == 1
    assert Path(versions[0]["dest"]).read_text(encoding="utf-8") == "old\n"
    assert not list(tmp_path.glob(".agw-file-*"))


def test_write_absent_dry_run_creates_no_file_or_recovery_record(tmp_path):
    target = tmp_path / "new.txt"
    result = file_ops.write_text(
        str(target), "content", expected_hash="absent", dry_run=True,
    )
    assert result["dry_run"] is True
    assert not target.exists()
    assert store.discover_archive_transactions() == []


def test_bounded_file_read_returns_hash_metadata_and_continuation(tmp_path):
    target = tmp_path / "app.log"
    target.write_bytes(b"one\ntwo\nthree\nfour\n")

    first = file_ops.read_text_page(str(target), limit=2)
    assert first["content"] == "one\ntwo\n"
    assert first["sha256"] == store.file_sha256(str(target))
    assert first["line_count"] == 4
    assert first["start_line"] == 1
    assert first["end_line"] == 2
    assert first["complete"] is False
    assert first["stop_reason"] == "limit"
    assert first["next_start_line"] == 3

    second = file_ops.read_text_page(str(target), start_line=3, limit=10)
    assert second["content"] == "three\nfour\n"
    assert second["complete"] is True
    assert second["next_start_line"] is None
    assert store.discover_archive_transactions() == []


def test_file_read_byte_bound_returns_only_complete_lines(tmp_path):
    target = tmp_path / "data.txt"
    target.write_bytes(b"alpha\nbeta\ngamma\n")
    result = file_ops.read_text_page(str(target), limit=10, max_bytes=11)
    assert result["content"] == "alpha\nbeta\n"
    assert result["returned_bytes"] == 11
    assert result["stop_reason"] == "max_bytes"
    assert result["next_start_line"] == 3


def test_file_read_oversized_unicode_line_returns_exact_byte_continuations(tmp_path):
    target = tmp_path / "map.txt"
    original = ("🗺 route " * 20) + "\nnext\n"
    target.write_text(original, encoding="utf-8", newline="")

    chunks = []
    page = file_ops.read_text_page(str(target), max_bytes=31)
    while page["next_start_byte"] is not None:
        assert page["partial_line"] is True
        assert page["returned_bytes"] <= 31
        chunks.append(page["content"])
        page = file_ops.read_text_page(
            str(target), start_byte=page["next_start_byte"], max_bytes=31,
        )
    chunks.append(page["content"])

    assert "".join(chunks) == original.splitlines(keepends=True)[0]
    assert page["partial_line"] is False
    assert page["next_start_line"] == 2
    final = file_ops.read_text_page(str(target), start_line=page["next_start_line"])
    assert final["content"] == "next\n"
    assert final["complete"] is True


def test_file_read_rejects_guessed_byte_offsets_and_explains_budget(tmp_path):
    target = tmp_path / "unicode.txt"
    target.write_text("🗺 map\n", encoding="utf-8")
    with pytest.raises(file_ops.FileOperationError, match="exact next_start_byte"):
        file_ops.read_text_page(str(target), start_byte=1)
    with pytest.raises(file_ops.FileOperationError, match="usually omit") as caught:
        file_ops.read_text_page(
            str(target), max_bytes=file_ops.MAX_READ_OUTPUT_BYTES + 1,
        )
    assert caught.value.details["default_bytes"] == file_ops.DEFAULT_READ_BYTES
    assert caught.value.details["maximum_bytes"] == file_ops.MAX_READ_OUTPUT_BYTES


def test_file_read_refuses_placeholder_before_open(tmp_path, monkeypatch):
    target = tmp_path / "cloud.txt"
    target.write_text("not opened", encoding="utf-8")
    monkeypatch.setattr(file_ops.profiles, "is_placeholder", lambda *a, **k: True)
    with pytest.raises(file_ops.FileOperationError) as caught:
        file_ops.read_text_page(str(target))
    assert caught.value.error_code == "placeholder_read_refused"


def test_file_read_json_stdout_is_strict_and_paginated(tmp_path):
    target = tmp_path / "notes.txt"
    target.write_bytes(b"first\nsecond\n")
    result = run_agw(
        "file", "read", str(target), "--limit", "1", "--json",
    )
    payload = json.loads(result.stdout)
    assert result.stderr == ""
    assert payload["content"] == "first\n"
    assert payload["next_start_line"] == 2
    assert payload["complete"] is False


def test_file_read_json_error_preserves_exact_unicode_path(tmp_path):
    target = tmp_path / "\U0001f5fa-\u00e9-\u65e5\u672c\u8a9e-missing.md"
    result = run_agw("file", "read", str(target), "--json", check=False)
    assert result.returncode != 0
    payload = json.loads(result.stderr)
    assert payload["error"]["details"]["path"] == str(target)
    assert target.name in payload["error"]["message"]
    assert target.name.encode("utf-8").decode("latin-1") not in \
        payload["error"]["message"]


def test_file_read_cli_uses_returned_byte_continuation(tmp_path):
    target = tmp_path / "one-line.json"
    target.write_text('{"map":"' + ("🗺" * 30) + '"}\n', encoding="utf-8")
    first = run_agw(
        "file", "read", str(target), "--max-bytes", "29", "--json",
    )
    payload = json.loads(first.stdout)
    assert payload["partial_line"] is True
    assert payload["next_start_byte"] > 0
    second = run_agw(
        "file", "read", str(target), "--start-byte",
        str(payload["next_start_byte"]), "--max-bytes", "29", "--json",
    )
    continuation = json.loads(second.stdout)
    assert continuation["start_byte"] == payload["next_start_byte"]


def test_exact_unified_patch_and_replace(tmp_path):
    target = tmp_path / "app.txt"
    target.write_text("alpha\nbeta\ngamma\n", encoding="utf-8")
    before = store.file_sha256(str(target))
    patch = "--- a/app.txt\n+++ b/app.txt\n@@ -1,3 +1,3 @@\n alpha\n-beta\n+BETA\n gamma\n"
    patched = file_ops.transform_text(
        str(target), lambda text: file_ops.apply_unified_patch(text, patch),
        expected_hash=before, operation="patch",
    )
    assert patched["changed"] == 1
    current = store.file_sha256(str(target))
    replaced = file_ops.transform_text(
        str(target), lambda text: file_ops.replace_text(text, "BETA", "beta2"),
        expected_hash=current, operation="replace",
    )
    assert replaced["changed"] == 1
    assert target.read_text(encoding="utf-8") == "alpha\nbeta2\ngamma\n"


def test_patch_context_conflict_creates_no_snapshot(tmp_path):
    target = tmp_path / "app.txt"
    target.write_text("actual\n", encoding="utf-8")
    patch = "@@ -1 +1 @@\n-expected\n+changed\n"
    with pytest.raises(file_ops.FileConflict, match="context"):
        file_ops.transform_text(
            str(target), lambda text: file_ops.apply_unified_patch(text, patch),
            operation="patch",
        )
    assert store.list_versions(str(target)) == []


def test_transform_without_expected_hash_rejects_concurrent_external_edit(tmp_path):
    target = tmp_path / "data.json"
    target.write_text('{"value":1}\n', encoding="utf-8")

    def transform(original):
        target.write_text('{"value":2,"source":"app"}\n', encoding="utf-8")
        return original.replace("1", "3")

    with pytest.raises(file_ops.FileConflict, match="transformation was prepared"):
        file_ops.transform_text(str(target), transform, operation="replace")

    assert target.read_text(encoding="utf-8") == \
        '{"value":2,"source":"app"}\n'
    assert store.list_versions(str(target)) == []


def test_declared_run_snapshots_output_and_captures_result(tmp_path):
    output = tmp_path / "tracker.xlsx"
    output.write_bytes(b"old workbook")
    script = tmp_path / "build_tracker.py"
    script.write_text(
        "from pathlib import Path\nPath('tracker.xlsx').write_bytes(b'new workbook')\n"
        "print('built')\n",
        encoding="utf-8",
    )
    before = store.file_sha256(str(output))
    result = file_ops.run_declared(
        [sys.executable, str(script)], [str(output)],
        expected_hashes=[before], cwd=str(tmp_path),
    )
    assert result["ok"] is True
    assert result["stdout_tail"].strip() == "built"
    assert output.read_bytes() == b"new workbook"
    assert result["outputs"][0]["before_hash"] == before
    assert len(store.list_versions(str(output))) == 1


def test_declared_run_dry_run_does_not_execute_or_snapshot(tmp_path):
    output = tmp_path / "not-created.txt"
    result = file_ops.run_declared(
        ["definitely-not-a-command"], [str(output)],
        expected_hashes=["absent"], cwd=str(tmp_path), dry_run=True,
    )
    assert result["executed"] is False
    assert not output.exists()
    assert store.discover_archive_transactions() == []


def test_declared_run_reports_missing_new_output(tmp_path):
    output = tmp_path / "missing.txt"
    script = tmp_path / "no_output.py"
    script.write_text("print('no output')\n", encoding="utf-8")
    result = file_ops.run_declared(
        [sys.executable, str(script)], [str(output)],
        expected_hashes=["absent"], cwd=str(tmp_path),
    )
    assert result["exit_code"] == 0
    assert result["ok"] is False
    assert result["declared_outputs_missing"] == [str(output)]
    records = store.discover_archive_transactions()
    assert len(records) == 1
    assert records[0]["record"]["kind"] == "absent_tombstone"


def test_declared_run_reports_undeclared_sidecar(tmp_path):
    output = tmp_path / "report.xlsx"
    sidecar = tmp_path / "report.xlsx.inspect.ndjson"
    script = tmp_path / "build.py"
    script.write_text(
        "from pathlib import Path\n"
        "Path('report.xlsx').write_bytes(b'book')\n"
        "Path('report.xlsx.inspect.ndjson').write_text('inspection')\n",
        encoding="utf-8",
    )
    result = file_ops.run_declared(
        [sys.executable, str(script)], [str(output)],
        expected_hashes=["absent"], cwd=str(tmp_path),
        output_roots=[str(tmp_path)],
    )
    assert result["ok"] is False
    assert result["undeclared_outputs"] == [{
        "path": str(sidecar), "change": "created", "kind": "file",
    }]
    assert result["unclaimed_observed_changes"] == result["undeclared_outputs"]
    assert result["output_observation"]["mode"] == "root_manifest"


def test_declared_sidecar_pattern_is_allowed(tmp_path):
    output = tmp_path / "report.xlsx"
    script = tmp_path / "build.py"
    script.write_text(
        "from pathlib import Path\n"
        "Path('report.xlsx').write_bytes(b'book')\n"
        "Path('report.xlsx.inspect.ndjson').write_text('inspection')\n",
        encoding="utf-8",
    )
    result = file_ops.run_declared(
        [sys.executable, str(script)], [str(output)],
        expected_hashes=["absent"], cwd=str(tmp_path),
        output_roots=[str(tmp_path)], output_patterns=["*.inspect.ndjson"],
    )
    assert result["ok"] is True
    assert result["undeclared_outputs"] == []


def test_exact_state_output_is_independent_of_dynamic_cache_root(tmp_path):
    state = tmp_path / "state"
    cache = tmp_path / "cache"
    state.mkdir()
    cache.mkdir()
    marker = state / "session.json"
    marker.write_text('{"status":"before"}\n', encoding="utf-8")
    sidecar = cache / "summon-a1b2c3.py"
    script = tmp_path / "summon.py"
    script.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "Path(sys.argv[1]).write_text('{\\\"status\\\":\\\"after\\\"}\\n')\n"
        "Path(sys.argv[2]).write_text('# cached runner\\n')\n",
        encoding="utf-8",
    )
    before = store.file_sha256(str(marker))

    result = file_ops.run_declared(
        [sys.executable, str(script), str(marker), str(sidecar)],
        [str(marker)], expected_hashes=[before], cwd=str(tmp_path),
        output_roots=[str(cache)], output_patterns=["summon-*.py"],
    )

    assert result["ok"] is True
    assert result["output_roots"] == [str(cache)]
    assert result["unclaimed_observed_changes"] == []
    assert marker.read_text(encoding="utf-8") == '{"status":"after"}\n'
    assert sidecar.read_text(encoding="utf-8") == "# cached runner\n"
    versions = store.list_versions(str(marker))
    assert len(versions) == 1
    assert Path(versions[0]["dest"]).read_text(encoding="utf-8") == \
        '{"status":"before"}\n'


def test_cli_dry_run_accepts_exact_output_outside_observed_root(tmp_path):
    state = tmp_path / "state"
    cache = tmp_path / "cache"
    state.mkdir()
    cache.mkdir()
    marker = state / "session.json"
    marker.write_text("before", encoding="utf-8")

    result = run_agw(
        "run", "--output", str(marker),
        "--expected-hash", store.file_sha256(str(marker)),
        "--output-root", str(cache),
        "--output-pattern", "summon-*.py",
        "--dry-run", "--json", "--", "not-started-during-dry-run",
    )
    payload = json.loads(result.stdout)

    assert payload["dry_run"] is True
    assert payload["executed"] is False
    assert payload["outputs"][0]["path"] == str(marker)
    assert payload["output_roots"] == [str(cache)]
    assert store.discover_archive_transactions() == []


def test_declared_exact_output_does_not_observe_parent_or_ambient_changes(
        tmp_path, monkeypatch):
    output = tmp_path / "report.xlsx"
    ambient = tmp_path / "data.json"
    ambient.write_text('{"value":1}\n', encoding="utf-8")
    script = tmp_path / "build.py"
    script.write_text(
        "from pathlib import Path\n"
        "Path('report.xlsx').write_bytes(b'book')\n"
        "Path('data.json').write_text('{\\\"value\\\":2}\\n')\n",
        encoding="utf-8",
    )

    def unexpected_observation(*args, **kwargs):
        raise AssertionError("exact output unexpectedly scanned its parent")

    monkeypatch.setattr(
        file_ops, "_observe_output_roots_bounded", unexpected_observation,
    )
    result = file_ops.run_declared(
        [sys.executable, str(script)], [str(output)],
        expected_hashes=["absent"], cwd=str(tmp_path),
    )

    assert result["ok"] is True
    assert result["undeclared_outputs"] == []
    assert result["unclaimed_observed_changes"] == []
    assert result["output_roots"] == []
    assert result["output_observation"] == {
        "mode": "exact_outputs", "complete": True,
        "files_before": 0, "files_after": 0, "changed_paths": 0,
        "unclaimed_changes": 0,
    }
    assert ambient.read_text(encoding="utf-8") == '{"value":2}\n'


def test_output_pattern_requires_explicit_observation_root(tmp_path):
    output = tmp_path / "report.xlsx"
    with pytest.raises(file_ops.FileOperationError, match="explicit --output-root"):
        file_ops.run_declared(
            [sys.executable, "-c", "pass"], [str(output)],
            expected_hashes=["absent"], cwd=str(tmp_path),
            output_patterns=["*.sidecar"], dry_run=True,
        )


def test_publish_staged_file_cross_directory_is_atomic_and_recoverable(tmp_path):
    target = tmp_path / "live" / "book.xlsx"
    target.parent.mkdir()
    target.write_bytes(b"old")
    stage = tmp_path / "build" / "book.xlsx"
    stage.parent.mkdir()
    stage.write_bytes(b"new")
    before = store.file_sha256(str(target))
    staged_hash = store.file_sha256(str(stage))
    result = file_ops.publish_staged_file(
        str(target), str(stage), expected_hash=before,
        expected_stage_hash=staged_hash,
    )
    assert target.read_bytes() == b"new"
    assert stage.read_bytes() == b"new"
    assert result["publish_attempts"] == 1
    assert Path(store.list_versions(str(target))[0]["dest"]).read_bytes() == b"old"


def test_publish_busy_preserves_live_and_stage(tmp_path, monkeypatch):
    target = tmp_path / "book.xlsx"
    stage = tmp_path / ".stage.xlsx"
    target.write_bytes(b"old")
    stage.write_bytes(b"new")
    before = store.file_sha256(str(target))

    def busy(source, live, _retry_seconds):
        raise file_ops.PublishBusy(
            "busy", {"staged": source, "target": live, "errno": errno.EBUSY}
        )

    monkeypatch.setattr(file_ops, "replace_with_retry", busy)
    with pytest.raises(file_ops.PublishBusy):
        file_ops.publish_staged_file(
            str(target), str(stage), expected_hash=before, retry_seconds=0,
        )
    assert target.read_bytes() == b"old"
    assert stage.read_bytes() == b"new"


def test_cli_publish_file_validates_stage_and_publishes(tmp_path, agw_home):
    target = tmp_path / "live.bin"
    stage = tmp_path / "build.bin"
    target.write_bytes(b"old")
    stage.write_bytes(b"new")
    result = run_agw(
        "publish-file", "--staged", str(stage), "--target", str(target),
        "--expected-hash", store.file_sha256(str(target)),
        "--expected-staged-hash", store.file_sha256(str(stage)), "--json",
        env={"AGW_HOME": agw_home},
    )
    data = json.loads(result.stdout)
    assert data["changed"] == 1
    assert data["publish_attempts"] == 1
    assert target.read_bytes() == b"new"


def test_output_observer_worker_is_reaped(tmp_path):
    import multiprocessing

    output = tmp_path / "out.txt"
    script = tmp_path / "build.py"
    script.write_text(
        "from pathlib import Path\nPath('out.txt').write_text('done')\n",
        encoding="utf-8",
    )
    file_ops.run_declared(
        [sys.executable, str(script)], [str(output)],
        expected_hashes=["absent"], cwd=str(tmp_path),
    )
    assert not [child for child in multiprocessing.active_children()
                if child.name == "agw-output-observer"]


def test_archive_json_stdout_is_json_only(tmp_path, agw_home):
    target = tmp_path / "archive-me.txt"
    target.write_text("recoverable", encoding="utf-8")
    result = run_agw(
        "archive", str(target), "--json", env={"AGW_HOME": agw_home},
    )
    assert result.stdout.count("\n") == 1
    data = json.loads(result.stdout)
    assert len(data) == 1
    assert data[0]["src"] == str(target)
    assert result.stderr == ""


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_cli_unlink_link_records_target_and_does_not_touch_contents(tmp_path, agw_home):
    target = tmp_path / "junction target"
    target.mkdir()
    sentinel = target / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    link = tmp_path / "junction link"
    created = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if created.returncode:
        pytest.skip(created.stderr or created.stdout)
    result = run_agw(
        "unlink-link", str(link), "--expected-target", str(target), "--json",
        env={"AGW_HOME": agw_home},
    )
    data = json.loads(result.stdout)
    assert data["link_type"] == "junction"
    assert data["archive"]["artifact_kind"] == "link-metadata"
    assert not os.path.lexists(link)
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_cli_file_write_from_stdin_is_compact_json(tmp_path, agw_home):
    target = tmp_path / "created.txt"
    result = run_agw(
        "file", "write", str(target), "--content-file", "-",
        "--expected-hash", "absent", "--json",
        env={"AGW_HOME": agw_home}, input_text="hello 👥\n",
    )
    data = json.loads(result.stdout)
    assert data["changed"] == 1
    assert target.read_text(encoding="utf-8") == "hello 👥\n"
    assert result.stderr == ""
