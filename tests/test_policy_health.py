"""Policy health and revision fail-closed contracts."""
import json
import os

import pytest

from core import engine, policy_health
from core.events import DENY, DEFER, MCP, READ, WRITE, ToolEvent


REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugin")


def _event(kind, path=""):
    return ToolEvent(kind=kind, tool="Read" if kind == READ else "Write",
                     paths=[path] if path else [], content="safe text")


def test_healthy_policy_has_stable_privacy_safe_revision():
    first = engine.load_policy(REPO)
    second = engine.load_policy(REPO)
    assert first.health == policy_health.HEALTHY
    assert first.revision == second.revision
    assert len(first.revision) == 64
    assert set(first.health_record.audit_metadata()) == {
        "policy_health", "policy_revision"
    }


def test_custom_policy_change_changes_revision(tmp_path, agw_home):
    directory = tmp_path / "agw-home" / "policies.d"
    directory.mkdir(parents=True)
    custom = directory / "company.json"
    custom.write_text(json.dumps({"settings": {"level": "standard"}}))
    first = engine.load_policy(REPO)
    custom.write_text(json.dumps({"settings": {"level": "strict"}}))
    second = engine.load_policy(REPO)
    assert first.health == second.health == policy_health.HEALTHY
    assert first.revision != second.revision


def test_invalid_custom_policy_allows_only_routine_reads(tmp_path, agw_home):
    directory = tmp_path / "agw-home" / "policies.d"
    directory.mkdir(parents=True)
    (directory / "broken.yaml").write_text("commands:\n  - pattern: [unclosed")
    ordinary = tmp_path / "ordinary.txt"
    ordinary.write_text("ordinary notes")
    policy = engine.load_policy(REPO)

    read = engine.evaluate(_event(READ, str(ordinary)), policy, REPO)
    write = engine.evaluate(_event(WRITE, str(ordinary)), policy, REPO)
    external = engine.evaluate(
        ToolEvent(kind=MCP, tool="mcp__drive__search_files"), policy, REPO
    )
    assert policy.health == policy_health.DEGRADED
    assert read.action == DEFER
    assert read.policy_revision == policy.revision
    assert write.action == DENY and write.rule_id == "policy:health-degraded"
    assert external.action == DENY and external.rule_id == "policy:health-degraded"


def test_invalid_custom_allow_rule_never_relaxes_baseline(agw_home):
    directory = os.path.join(agw_home, "policies.d")
    os.makedirs(directory)
    with open(os.path.join(directory, "mixed.json"), "w", encoding="utf-8") as handle:
        json.dump({
            "commands": [
                {"pattern": "rm *", "action": "allow", "reason": "unsafe override"},
                {"pattern": ["invalid"], "action": "allow"},
            ]
        }, handle)
    policy = engine.load_policy(REPO)
    decision = engine.evaluate(
        ToolEvent(kind="exec", tool="Bash", command="rm important.txt"), policy, REPO
    )
    assert policy.health == policy_health.DEGRADED
    assert decision.action == DENY


def test_missing_baseline_is_unavailable_and_denies_reads(tmp_path):
    empty_plugin = tmp_path / "empty-plugin"
    empty_plugin.mkdir()
    ordinary = tmp_path / "ordinary.txt"
    ordinary.write_text("ordinary notes")
    policy = engine.load_policy(str(empty_plugin))
    decision = engine.evaluate(_event(READ, str(ordinary)), policy, str(empty_plugin))
    assert policy.health == policy_health.UNAVAILABLE
    assert decision.action == DENY
    assert decision.rule_id == "policy:health-unavailable"


@pytest.mark.parametrize("baseline", [
    None,
    "commands:\n  - pattern: [unclosed",
    "- not-a-mapping\n",
    "snippets:\n  - pattern: '[unterminated'\n    action: deny\n",
])
def test_baseline_failure_matrix_is_unavailable(tmp_path, baseline):
    plugin = tmp_path / "plugin"
    policies = plugin / "policies"
    policies.mkdir(parents=True)
    if baseline is not None:
        (policies / "core.yaml").write_text(baseline)
    target = tmp_path / "ordinary.txt"
    target.write_text("ordinary")
    policy = engine.load_policy(str(plugin))
    decision = engine.evaluate(_event(READ, str(target)), policy, str(plugin))
    assert policy.health == policy_health.UNAVAILABLE
    assert decision.action == DENY
    assert decision.rule_id == "policy:health-unavailable"


@pytest.mark.parametrize(("filename", "document"), [
    ("bad-type.json", json.dumps({
        "commands": [
            {"pattern": "echo custom*", "action": "ask"},
            {"pattern": ["not-a-string"], "action": "allow"},
        ],
        "settings": {"level": "relaxed"},
    })),
    ("bad-path.yaml", """
commands:
  - pattern: "echo custom*"
    action: ask
paths:
  - glob: 42
    zone: no-access
settings:
  level: relaxed
"""),
    ("bad-zone.json", json.dumps({
        "commands": [{"pattern": "echo custom*", "action": "ask"}],
        "paths": [{"glob": "C:/private/**", "zone": "invalid-zone"}],
    })),
    ("bad-regex.yaml", """
commands:
  - pattern: "echo custom*"
    action: ask
snippets:
  - pattern: "[unterminated"
    action: deny
"""),
])
def test_custom_failure_matrix_is_degraded_and_atomic(
        tmp_path, agw_home, filename, document):
    directory = tmp_path / "agw-home" / "policies.d"
    directory.mkdir(parents=True)
    (directory / filename).write_text(document)
    policy = engine.load_policy(REPO)
    assert policy.health == policy_health.DEGRADED
    assert not any(rule["id"].startswith(filename + ":")
                   for rule in policy.command_rules + policy.path_rules)
    assert policy.settings.get("level") != "relaxed"


@pytest.fixture()
def without_pyyaml(monkeypatch):
    """Force the stdlib-only reader, the plugin's documented primary mode."""
    import sys

    monkeypatch.setitem(sys.modules, "yaml", None)  # `import yaml` -> ImportError
    return None


# Everything PyYAML rejects among the constructs core.yaml actually uses.
# miniyaml is the only policy reader when PyYAML is absent, so a shape it
# accepts as a plain string is a corrupt pack that loads as HEALTHY.
MINIYAML_REJECTS = [
    "commands:\n  - pattern: [unclosed",
    "k: [unclosed",
    "k: [a, [b]",
    "k: [a] [b]",
    "k: {unclosed",
    "k: {a: 1}",
    "k: ]stray",
    "k: }stray",
    'k: "unterminated',
    "k: 'unterminated",
    "commands:\n\t- pattern: rm *\n",
    "commands:\n  - pattern: rm *\n\taction: deny\n",
]
MINIYAML_ACCEPTS = [
    ("k: [a, b]", {"k": ["a", "b"]}),
    ("k: []", {"k": []}),
    ('applies_to: ["*.py", "*.js"]', {"applies_to": ["*.py", "*.js"]}),
    ('k: "AKIA[0-9A-Z]{16}"', {"k": "AKIA[0-9A-Z]{16}"}),
    ("k: a]b", {"k": "a]b"}),
    ("k: a[b", {"k": "a[b"}),
    ("k: don't stop", {"k": "don't stop"}),
    ("snippets:\n  - pattern: '[unterminated'\n    action: deny\n",
     {"snippets": [{"pattern": "[unterminated", "action": "deny"}]}),
]


@pytest.mark.parametrize("document", MINIYAML_REJECTS)
def test_miniyaml_rejects_the_documents_pyyaml_rejects(document):
    from core import miniyaml

    with pytest.raises(miniyaml.MiniYamlError):
        miniyaml.loads(document)


@pytest.mark.parametrize("document,expected", MINIYAML_ACCEPTS)
def test_miniyaml_still_reads_the_shapes_core_yaml_uses(document, expected):
    from core import miniyaml

    assert miniyaml.loads(document) == expected


def test_shipped_core_policy_parses_under_the_stdlib_reader():
    from core import miniyaml

    with open(os.path.join(REPO, "policies", "core.yaml"), encoding="utf-8") as fh:
        data = miniyaml.loads(fh.read())
    assert isinstance(data, dict) and data.get("commands")


@pytest.mark.parametrize("document", MINIYAML_REJECTS)
def test_corrupt_custom_pack_is_degraded_without_pyyaml(
        tmp_path, agw_home, without_pyyaml, document):
    directory = tmp_path / "agw-home" / "policies.d"
    directory.mkdir(parents=True)
    (directory / "broken.yaml").write_text(document)
    policy = engine.load_policy(REPO)
    assert policy.health == policy_health.DEGRADED


@pytest.mark.parametrize("document", MINIYAML_REJECTS)
def test_corrupt_baseline_is_unavailable_without_pyyaml(
        tmp_path, without_pyyaml, document):
    plugin = tmp_path / "plugin"
    policies = plugin / "policies"
    policies.mkdir(parents=True)
    (policies / "core.yaml").write_text(document)
    policy = engine.load_policy(str(plugin))
    assert policy.health == policy_health.UNAVAILABLE


def test_custom_policy_discovery_failure_is_degraded(monkeypatch, agw_home):
    original = engine._policy_files
    local = os.path.normcase(os.path.abspath(os.path.join(agw_home, "policies.d")))

    def fail_local(directory, suffixes=(".yaml", ".yml", ".json")):
        if os.path.normcase(os.path.abspath(directory)) == local:
            return [], True
        return original(directory, suffixes)

    monkeypatch.setattr(engine, "_policy_files", fail_local)
    policy = engine.load_policy(REPO)
    assert policy.health == policy_health.DEGRADED
    assert "policy-directory-unavailable" in policy.degraded
