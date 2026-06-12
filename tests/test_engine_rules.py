"""Engine behavior beyond the corpus: redirects, tiers, write/read guards."""
import json
import os

from core import engine
from core.events import ALLOW, ASK, DENY, DEFER, EDIT, MCP, READ, WRITE, ToolEvent

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _ev(kind, **kw):
    return ToolEvent(kind=kind, tool=kw.pop("tool", "Write"), **kw)


def test_rm_redirect_teaches_agw(evaluate):
    d = evaluate("rm -rf docs/")
    assert d.action == DENY
    assert "agw archive" in d.reason and "agw restore" in d.reason


def test_agw_verbs_allowed(evaluate):
    assert evaluate("agw archive file.docx").action == ALLOW
    assert evaluate("agw checkout report.docx").action == ALLOW


def test_agw_prune_always_asks(evaluate):
    assert evaluate("agw prune --yes-i-am-a-human").action == ASK


def test_git_checkout_branch_vs_discard(evaluate):
    assert evaluate("git checkout -b feature").action in (DEFER, ALLOW)
    assert evaluate("git checkout -- file.py").action == ASK


def test_unparseable_fails_closed(evaluate):
    d = evaluate("rm 'unterminated")
    assert d.action in (ASK, DENY)


def test_deeply_nested_fails_closed(evaluate):
    cmd = "echo hi"
    for _ in range(10):
        cmd = f"echo $({cmd})"
    assert evaluate(cmd).action in (ASK, DENY)


def test_write_protected_plugin_path(policy):
    target = os.path.join(REPO, "policies", "core.yaml")
    d = engine.evaluate(_ev(WRITE, paths=[target], content="x"), policy, REPO)
    assert d.action == DENY


def test_write_archive_store_denied(policy, agw_home):
    target = os.path.join(agw_home, "archive", "x.txt")
    d = engine.evaluate(_ev(WRITE, paths=[target], content="x"), policy, REPO)
    assert d.action == DENY


def test_gdoc_stub_write_denied(policy, tmp_path):
    stub = tmp_path / "Budget.gsheet"
    stub.write_text(json.dumps({"url": "https://docs.google.com/x", "doc_id": "x"}))
    d = engine.evaluate(_ev(WRITE, paths=[str(stub)], content="new"), policy, REPO)
    assert d.action == DENY
    assert "stub" in d.reason or "pointer" in d.reason


def test_placeholder_write_denied(policy, tmp_path):
    # sparse file: st_blocks == 0, st_size > 0 — the cloud-placeholder signature
    placeholder = tmp_path / "report.docx"
    with open(placeholder, "wb") as f:
        f.truncate(1024 * 1024)
    st = os.stat(placeholder)
    if st.st_blocks != 0:  # filesystem doesn't support sparse files
        import pytest
        pytest.skip("no sparse-file support on this filesystem")
    d = engine.evaluate(_ev(WRITE, paths=[str(placeholder)], content="x"), policy, REPO)
    assert d.action == DENY
    assert "placeholder" in d.reason.lower() or "cloud-only" in d.reason.lower()


def test_placeholder_read_asks(policy, tmp_path):
    placeholder = tmp_path / "data.xlsx"
    with open(placeholder, "wb") as f:
        f.truncate(512 * 1024)
    if os.stat(placeholder).st_blocks != 0:
        import pytest
        pytest.skip("no sparse-file support")
    d = engine.evaluate(_ev(READ, tool="Read", paths=[str(placeholder)]), policy, REPO)
    assert d.action == ASK


def test_shrink_guard(policy, tmp_path):
    big = tmp_path / "big.csv"
    big.write_text("x" * 200_000)
    d = engine.evaluate(_ev(WRITE, paths=[str(big)], content="tiny"), policy, REPO)
    assert d.action == ASK
    assert "shrink" in d.reason.lower() or "truncated" in d.reason.lower()


def test_normal_write_defers_and_snapshots_nothing_weird(policy, tmp_path):
    f = tmp_path / "notes.md"
    f.write_text("hello")
    d = engine.evaluate(_ev(WRITE, paths=[str(f)], content="hello world"), policy, REPO)
    assert d.action in (DEFER, ALLOW)


def test_snippet_rule_blocks_private_key(policy, tmp_path):
    d = engine.evaluate(_ev(WRITE, paths=[str(tmp_path / "key.pem")],
                            content="-----BEGIN RSA PRIVATE KEY-----\nabc"), policy, REPO)
    assert d.action == DENY


def test_zone_rules(tmp_path, agw_home):
    pol_dir = os.path.join(agw_home, "policies.d")
    os.makedirs(pol_dir)
    with open(os.path.join(pol_dir, "zones.yaml"), "w") as f:
        f.write(f"paths:\n  - glob: \"{tmp_path}/secret/**\"\n    zone: no-access\n")
    policy = engine.load_policy(REPO)
    target = str(tmp_path / "secret" / "f.txt")
    assert engine.evaluate(_ev(WRITE, paths=[target], content="x"),
                           policy, REPO).action == DENY
    assert engine.evaluate(_ev(READ, tool="Read", paths=[target]),
                           policy, REPO).action == DENY


def test_mcp_delete_denied(policy):
    d = engine.evaluate(_ev(MCP, tool="mcp__google_drive__delete_file"), policy, REPO)
    assert d.action == DENY


def test_mcp_read_defers(policy):
    d = engine.evaluate(_ev(MCP, tool="mcp__google_drive__search_files"), policy, REPO)
    assert d.action == DEFER


def test_corrupt_policy_pack_degrades_with_warning(agw_home):
    pol_dir = os.path.join(agw_home, "policies.d")
    os.makedirs(pol_dir)
    with open(os.path.join(pol_dir, "broken.yaml"), "w") as f:
        f.write("commands:\n  - pattern: [unclosed\n      ::bad")
    policy = engine.load_policy(REPO)
    assert "broken.yaml" in policy.degraded
    # builtin guards still work
    d = engine.evaluate(ToolEvent(kind="exec", tool="Bash", command="rm -rf x"),
                        policy, REPO)
    assert d.action == DENY
