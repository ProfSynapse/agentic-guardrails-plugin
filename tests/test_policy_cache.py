"""The persisted policy cache: faster, never different.

Every test here asserts an equality with the uncached loader or a fall-through
to it. The cache is allowed to change how long load_policy takes and nothing
else.
"""
import json
import os
import subprocess
import sys

import pytest

from core import engine, policy_health, policycache
from core.events import EXEC, MCP, READ, WRITE, ToolEvent

REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugin")
START = os.path.join(REPO, "scripts", "claude", "sessionstart.py")


def _cache_file(agw_home):
    return os.path.join(agw_home, policycache.FILE_NAME)


def _snapshot(policy):
    """Everything a decision can depend on, as comparable data."""
    return {
        "health": policy.health, "revision": policy.revision,
        "baseline_revision": policy.baseline_revision,
        "degraded": list(policy.degraded), "settings": policy.settings,
        "commands": policy.command_rules, "paths": policy.path_rules,
        "mcp": policy.mcp_rules,
        "snippets": [dict(r, pattern=r["pattern"].pattern) for r in policy.snippet_rules],
        "protected": policy.protected_globs,
        "issues": policy.health_record.issue_codes,
    }


def _custom_pack(agw_home, name, text):
    directory = os.path.join(agw_home, "policies.d")
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def _no_parse(monkeypatch):
    def _boom(path, raw):
        raise AssertionError("a cache hit must not parse %s" % path)
    monkeypatch.setattr(engine, "_load_policy_document", _boom)


def test_hit_skips_parsing_and_is_identical(agw_home, monkeypatch):
    first = engine.load_policy(REPO)
    assert first.health == policy_health.HEALTHY
    assert os.path.isfile(_cache_file(agw_home))
    _no_parse(monkeypatch)
    second = engine.load_policy(REPO)
    assert _snapshot(second) == _snapshot(first)


def test_policy_edit_invalidates_the_cache(agw_home, monkeypatch):
    pack = _custom_pack(agw_home, "company.yaml",
                        "commands:\n  - pattern: 'frobnicate-alpha'\n    action: deny\n")
    first = engine.load_policy(REPO)
    assert first.health == policy_health.HEALTHY
    assert any("frobnicate-alpha" in r["pattern"] for r in first.command_rules)
    with open(pack, "w", encoding="utf-8") as fh:
        fh.write("commands:\n  - pattern: 'frobnicate-beta'\n    action: ask\n")
    st = os.stat(pack)
    os.utime(pack, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
    second = engine.load_policy(REPO)
    assert second.health == policy_health.HEALTHY
    assert second.revision != first.revision
    assert any("frobnicate-beta" in r["pattern"] for r in second.command_rules)
    assert not any("frobnicate-alpha" in r["pattern"] for r in second.command_rules)
    # A new pack appearing in the directory is a change too.
    _custom_pack(agw_home, "more.json", json.dumps({"settings": {"level": "strict"}}))
    third = engine.load_policy(REPO)
    assert third.settings.get("level") == "strict"
    assert third.revision != second.revision


@pytest.mark.parametrize("garbage", [
    b"not json at all",
    b"[]",
    b'{"schema": "agw.policy-cache/0", "key": {}, "policy": {}}',
    b'{"schema": "agw.policy-cache/1", "key": {"files": []}, "policy": {}}',
    b"\xff\xfe\x00",
])
def test_corrupt_cache_is_ignored_and_rewritten(agw_home, garbage):
    expected = _snapshot(engine.load_policy(REPO))
    with open(_cache_file(agw_home), "wb") as fh:
        fh.write(garbage)
    assert _snapshot(engine.load_policy(REPO)) == expected
    with open(_cache_file(agw_home), "rb") as fh:
        assert json.loads(fh.read())["schema"] == policycache.SCHEMA


def test_unrebuildable_cached_document_falls_through(agw_home):
    """A matching key with a document this loader cannot rebuild is malformed."""
    expected = _snapshot(engine.load_policy(REPO))
    with open(_cache_file(agw_home), encoding="utf-8") as fh:
        cached = json.load(fh)
    cached["policy"]["snippet_rules"] = [{"pattern": "(unclosed", "enforcement_class": "advisory"}]
    with open(_cache_file(agw_home), "w", encoding="utf-8") as fh:
        json.dump(cached, fh)
    assert _snapshot(engine.load_policy(REPO)) == expected


def test_degraded_policy_is_identical_with_and_without_cache(agw_home):
    healthy = engine.load_policy(REPO)
    assert healthy.health == policy_health.HEALTHY
    _custom_pack(agw_home, "broken.yaml", "commands:\n  - pattern: [unclosed")
    with_cache = engine.load_policy(REPO)
    os.unlink(_cache_file(agw_home))
    without_cache = engine.load_policy(REPO)
    assert with_cache.health == without_cache.health == policy_health.DEGRADED
    assert _snapshot(with_cache) == _snapshot(without_cache)
    assert "broken.yaml" in with_cache.degraded
    # A degraded result is never stored, so fixing the pack cannot be masked.
    assert not os.path.exists(_cache_file(agw_home))


def test_unavailable_policy_is_identical_with_and_without_cache(agw_home, tmp_path):
    empty_plugin = tmp_path / "empty-plugin"
    empty_plugin.mkdir()
    engine.load_policy(REPO)  # a healthy cache for a *different* plugin root
    with_cache = engine.load_policy(str(empty_plugin))
    os.unlink(_cache_file(agw_home))
    without_cache = engine.load_policy(str(empty_plugin))
    assert with_cache.health == without_cache.health == policy_health.UNAVAILABLE
    assert _snapshot(with_cache) == _snapshot(without_cache)


def test_cache_never_changes_a_decision(agw_home, tmp_path):
    secret = tmp_path / ".env"
    secret.write_text("TOKEN=abcdef123456\n")
    plain = tmp_path / "notes.txt"
    plain.write_text("plain notes\n")
    events = [
        ToolEvent(kind=READ, tool="Read", paths=[str(plain)]),
        ToolEvent(kind=READ, tool="Read", paths=[str(secret)]),
        ToolEvent(kind=WRITE, tool="Write", paths=[str(plain)], content="x"),
        ToolEvent(kind=EXEC, tool="Bash", command="rm -rf %s" % tmp_path, cwd=str(tmp_path)),
        ToolEvent(kind=EXEC, tool="Bash", command="git status", cwd=str(tmp_path)),
        ToolEvent(kind=EXEC, tool="Bash", command="pip install requests", cwd=str(tmp_path)),
        ToolEvent(kind=MCP, tool="mcp__drive__delete_file"),
        ToolEvent(kind=MCP, tool="mcp__drive__search_files"),
    ]

    def _decide(policy):
        return [(d.action, d.rule_id, d.reason, d.memo_key, d.policy_revision, d.warnings)
                for d in (engine.evaluate(ev, policy, REPO) for ev in events)]

    uncached = _decide(engine.load_policy(REPO))
    assert os.path.isfile(_cache_file(agw_home))
    assert _decide(engine.load_policy(REPO)) == uncached
    # and the mix of outcomes is real, not all-defer
    assert {row[0] for row in uncached} >= {"deny", "ask", "defer"}


def test_unwritable_cache_never_fails_the_call(agw_home, monkeypatch):
    # AGW_HOME resolves to a regular file: no directory can be created there.
    blocker = os.path.join(os.path.dirname(agw_home), "blocker")
    with open(blocker, "w") as fh:
        fh.write("x")
    monkeypatch.setenv("AGW_HOME", blocker)
    policy = engine.load_policy(REPO)
    assert policy.health == policy_health.HEALTHY
    assert not os.path.exists(os.path.join(blocker, policycache.FILE_NAME))


def test_key_is_taken_before_the_packs_are_read(agw_home, monkeypatch):
    """A pack edited mid-parse must not be cached under its old stats."""
    pack = _custom_pack(agw_home, "race.yaml", "settings:\n  level: standard\n")
    real_read = engine._read_policy_bytes

    def _edit_during_read(path):
        raw = real_read(path)
        if path == pack and os.path.getsize(pack) < 40:
            with open(pack, "w", encoding="utf-8") as fh:
                fh.write("settings:\n  level: strict\n  session_memory: false\n")
            st = os.stat(pack)
            os.utime(pack, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
        return raw
    monkeypatch.setattr(engine, "_read_policy_bytes", _edit_during_read)
    first = engine.load_policy(REPO)
    assert first.settings.get("level") == "standard"
    monkeypatch.setattr(engine, "_read_policy_bytes", real_read)
    second = engine.load_policy(REPO)
    assert second.settings.get("level") == "strict"


def test_miniyaml_is_preferred_over_pyyaml(monkeypatch):
    yaml = pytest.importorskip("yaml")
    monkeypatch.setattr(yaml, "safe_load",
                        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("PyYAML used")))
    assert engine.load_policy(REPO).health == policy_health.HEALTHY


def test_pyyaml_is_only_a_fallback_for_what_miniyaml_rejects(monkeypatch, agw_home):
    from core import miniyaml
    calls = []
    real = miniyaml.loads

    def _reject(text):
        calls.append(text)
        raise miniyaml.MiniYamlError("rejected for the test")
    monkeypatch.setattr(miniyaml, "loads", _reject)
    policy = engine.load_policy(REPO)
    assert calls, "miniyaml was not consulted first"
    try:
        import yaml  # noqa: F401
    except ImportError:
        assert policy.health == policy_health.UNAVAILABLE
    else:
        assert policy.health == policy_health.HEALTHY
    monkeypatch.setattr(miniyaml, "loads", real)


def test_sessionstart_warms_the_cache(tmp_path):
    home = tmp_path / "home"
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=REPO, AGW_HOME=str(home))
    result = subprocess.run([sys.executable, START], input="{}", capture_output=True,
                            text=True, env=env, timeout=60)
    assert result.returncode == 0
    with open(_cache_file(str(home)), encoding="utf-8") as fh:
        cached = json.load(fh)
    assert cached["schema"] == policycache.SCHEMA
    assert cached["key"] == policycache.key(REPO, str(home))
