"""The persisted folder-profile cache: the marker walk's verdict survives the
process, is keyed on the directories it probed, expires, and never stores a
placeholder verdict for a file."""
import json
import os

import pytest

from core import profiles


def _fresh(agw_home=None):
    """Forget every in-process verdict so the next detect goes to disk."""
    profiles._cache.clear()
    profiles._persisted = None
    if agw_home:
        # The store root exists before detection runs (SessionStart makes it),
        # and creating it later would change an ancestor's mtime in the tests.
        os.makedirs(agw_home, exist_ok=True)


def _cache_file(agw_home):
    return os.path.join(agw_home, profiles._PROFILE_CACHE_NAME)


def _forbid_probes(monkeypatch):
    def _boom(_path):
        raise AssertionError("the marker walk ran although the cache had the answer")
    monkeypatch.setattr(profiles.os.path, "exists", _boom)


def test_verdict_survives_the_process(tmp_path, agw_home, monkeypatch):
    repo = tmp_path / "repo" / "src"
    repo.mkdir(parents=True)
    (tmp_path / "repo" / ".git").mkdir()
    _fresh(agw_home)
    assert profiles.detect(str(repo), assume_directory=True).name == "git"
    with open(_cache_file(agw_home), encoding="utf-8") as fh:
        entries = json.load(fh)["entries"]
    assert entries[str(repo)]["profile"] == "git"
    # A "new process": no in-memory state, and no probing allowed.
    _fresh()
    _forbid_probes(monkeypatch)
    assert profiles.detect(str(repo), assume_directory=True).name == "git"


def test_marker_change_in_an_ancestor_invalidates(tmp_path, agw_home):
    root = tmp_path / "sync"
    nested = root / "project"
    nested.mkdir(parents=True)
    _fresh(agw_home)
    assert profiles.detect(str(nested), assume_directory=True).name == "local"
    (root / ".dropbox").mkdir()
    _fresh()
    assert profiles.detect(str(nested), assume_directory=True).name == "dropbox"
    (root / ".dropbox").rmdir()
    _fresh()
    assert profiles.detect(str(nested), assume_directory=True).name == "local"


def test_entry_expires_after_the_ttl(tmp_path, agw_home, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    _fresh(agw_home)
    assert profiles.detect(str(project), assume_directory=True).name == "local"
    probes = []
    real_exists = profiles.os.path.exists
    monkeypatch.setattr(profiles.os.path, "exists",
                        lambda path: probes.append(path) or real_exists(path))
    _fresh()
    profiles.detect(str(project), assume_directory=True)
    assert not probes, "a fresh entry must be served without probing"
    later = profiles.time.time() + profiles._PROFILE_CACHE_TTL + 1
    monkeypatch.setattr(profiles.time, "time", lambda: later)
    _fresh()
    profiles.detect(str(project), assume_directory=True)
    assert probes, "an expired entry must be re-derived"


@pytest.mark.parametrize("garbage", [b"nope", b"[]", b'{"schema": "x", "entries": {}}',
                                     b'{"schema": "agw.profile-cache/1", "entries": []}'])
def test_corrupt_cache_is_ignored_and_rewritten(tmp_path, agw_home, garbage):
    project = tmp_path / "project"
    project.mkdir()
    os.makedirs(agw_home, exist_ok=True)
    with open(_cache_file(agw_home), "wb") as fh:
        fh.write(garbage)
    _fresh(agw_home)
    assert profiles.detect(str(project), assume_directory=True).name == "local"
    with open(_cache_file(agw_home), encoding="utf-8") as fh:
        assert str(project) in json.load(fh)["entries"]


def test_unwritable_home_never_fails_detection(tmp_path, monkeypatch):
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    monkeypatch.setenv("AGW_HOME", str(blocker))
    project = tmp_path / "project"
    project.mkdir()
    _fresh()
    assert profiles.detect(str(project), assume_directory=True).name == "local"


def test_only_folder_verdicts_are_stored_never_a_placeholder(tmp_path, agw_home):
    project = tmp_path / "project"
    project.mkdir()
    document = project / "report.docx"
    document.write_bytes(b"x" * 4096)
    _fresh(agw_home)
    assert profiles.detect(str(document)).name == "local"
    assert profiles.is_placeholder(str(document)) is False
    with open(_cache_file(agw_home), encoding="utf-8") as fh:
        entries = json.load(fh)["entries"]
    assert set(entries) == {str(project)}
    assert set(entries[str(project)]) == {"key", "profile", "at"}


def test_the_cache_is_bounded(tmp_path, agw_home, monkeypatch):
    monkeypatch.setattr(profiles, "_PROFILE_CACHE_MAX", 3)
    _fresh(agw_home)
    for index in range(5):
        directory = tmp_path / ("d%d" % index)
        directory.mkdir()
        profiles.detect(str(directory), assume_directory=True)
    with open(_cache_file(agw_home), encoding="utf-8") as fh:
        entries = json.load(fh)["entries"]
    assert len(entries) == 3
    assert str(tmp_path / "d4") in entries and str(tmp_path / "d0") not in entries


def test_detection_still_never_enumerates_ancestors(tmp_path, agw_home, monkeypatch):
    root = tmp_path / "sync"
    nested = root / "project"
    nested.mkdir(parents=True)
    (root / ".dropbox").mkdir()
    monkeypatch.setattr(profiles.os, "listdir", lambda _path: (_ for _ in ()).throw(
        AssertionError("profile detection enumerated an ancestor")))
    _fresh()
    assert profiles.detect(str(nested), assume_directory=True).name == "dropbox"
