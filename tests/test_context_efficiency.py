"""Budgets for progressively disclosed Guardrails context and CLI help."""
import math
import subprocess
import sys
from pathlib import Path

from claude import sessionstart as claude_start
from codex import sessionstart as codex_start


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugin"
AGW = PLUGIN / "scripts" / "agw" / "agw.py"

# Frozen measurements from the installed 0.3.3 surface before consolidation.
LEGACY_DISCOVERABLE_SKILL_CHARS = 16_176
LEGACY_OFFICE_HELP_CHARS = 3_740
LEGACY_SESSION_CONTEXT_CHARS = 3_945


def _help(*args):
    result = subprocess.run(
        [sys.executable, str(AGW), *args, "--help"],
        text=True, capture_output=True, check=True,
    )
    return result.stdout


def _estimated_tokens(text):
    """Stable dependency-free upper-level proxy for comparative token budgets."""
    return math.ceil(len(text) / 4)


def test_one_discoverable_skill_with_progressive_references():
    skill_files = sorted((PLUGIN / "skills").glob("*/SKILL.md"))
    assert [path.parent.name for path in skill_files] == ["agentic-guardrails"]

    root_text = skill_files[0].read_text(encoding="utf-8")
    assert len(root_text) < LEGACY_DISCOVERABLE_SKILL_CHARS * 0.20
    assert "exact host-supplied paths" in root_text
    assert "never infer or search plugin-" in root_text
    assert "approve Guardrails" in root_text and "host UI" in root_text
    assert "Never use a cache path or change PATH" in root_text
    assert "office <operation> --help" in root_text
    references = sorted((skill_files[0].parent / "references").glob("*.md"))
    assert {path.name for path in references} == {
        "diagnostics.md", "google-stubs.md", "office.md", "recovery.md",
        "synced-folders.md", "text-files.md", "trusted-workflows.md",
    }
    assert all(path.stat().st_size < 1_800 for path in references)


def test_always_on_context_is_small_and_has_no_operation_catalog():
    for context in (claude_start.CONTEXT, codex_start.CONTEXT):
        assert len(context) < LEGACY_SESSION_CONTEXT_CHARS * 0.60
        assert len(context.split()) <= 330
        assert "append-table-row" not in context
        assert "office <operation>" in context
        assert str(PLUGIN) not in context
        assert "trusted PreToolUse hook" in context
        assert "exact host-supplied `SKILL.md` location" in context
        assert "plugin-cache path" in context
        assert "agw workflow match -- <command>" in context


def test_session_workflow_discovery_is_bounded_and_workspace_relevant(tmp_path):
    items = [
        {
            "id": f"example.workflow-{index}", "verified": True,
            "script": str(tmp_path / f"script-{index}.py"),
        }
        for index in range(6)
    ]
    for module in (claude_start, codex_start):
        note = module._workflow_note(items, str(tmp_path))
        assert "6 verified" in note
        assert "workflow match" in note
        assert "example.workflow-0" in note
        assert "example.workflow-2" in note
        assert "example.workflow-3" not in note


def test_short_launcher_removes_repeated_package_path_tokens():
    operation = " run --json --output artifact.xlsx -- node build.mjs"
    for platform, short, binary in (
        ("nt", "agw", PLUGIN / "bin" / "agw.cmd"),
        ("posix", "agw", PLUGIN / "bin" / "agw"),
    ):
        legacy = f'"{binary}"{operation}'
        compact = f"{short}{operation}"
        assert _estimated_tokens(compact) < _estimated_tokens(legacy) * 0.65
        module_value = claude_start._launcher(platform)
        assert module_value == short
        assert codex_start._launcher(platform) == short


def test_always_on_context_encodes_operating_principles():
    for context in (claude_start.CONTEXT, codex_start.CONTEXT):
        lower = context.lower()
        assert "resolve exact targets" in lower
        assert "name every target literally" in lower
        assert "variables, globs" in lower
        assert "separate discovery/read" in lower
        assert "do not bundle unrelated writes" in lower
        assert "smallest reversible operation" in lower
        assert "declare every output" in lower
        assert "exact mode scans no siblings" in lower
        assert "block or ask as constraint information" in lower
        assert "retry only with a simpler, exact operation" in lower
        assert "request it once" in lower
        assert "stop on conflicts" in lower
        assert "instead of forcing" in lower


def test_help_progressively_excludes_unrelated_options():
    top = _help()
    office = _help("office")
    append = _help("office", "append-table-row")

    # A complete intent index is worth a small fixed cost because it prevents
    # trial-and-error verb help calls when the family is unknown.
    assert len(top) <= 1_700
    assert "--row-json" not in top
    assert len(office) < LEGACY_OFFICE_HELP_CHARS * 0.35
    assert "append-table-row" in office
    assert "--row-json" not in office
    assert "--find" not in office
    assert "--row-json" in append
    assert "--unique-column" in append
    assert "--find" not in append
    assert "--cell" not in append
    assert len(append) < LEGACY_OFFICE_HELP_CHARS * 0.50


def test_common_office_help_paths_reduce_tokens_without_extra_round_trip():
    # The routing skill names common operations, so a known intent goes directly
    # to one leaf help call. Even an unknown Office intent (family + leaf) emits
    # less context than the former single flat Office help page.
    family = _help("office")
    leaf = _help("office", "append-table-row")
    assert _estimated_tokens(leaf) < _estimated_tokens("x" * LEGACY_OFFICE_HELP_CHARS)
    assert _estimated_tokens(family + leaf) < \
        _estimated_tokens("x" * LEGACY_OFFICE_HELP_CHARS)


def test_office_inspect_alias_and_unknown_operation_guidance_are_compact():
    alias = subprocess.run(
        [sys.executable, str(AGW), "office", "inspect", "--help"],
        text=True, capture_output=True, check=True,
    )
    assert "Inspect Office structure and risks" in alias.stdout

    unknown = subprocess.run(
        [sys.executable, str(AGW), "office", "not-an-operation"],
        text=True, capture_output=True, check=False,
    )
    assert unknown.returncode == 2
    assert unknown.stdout == ""
    assert "unknown Office operation" in unknown.stderr
    assert "agw office --help" in unknown.stderr
    assert "choose from" not in unknown.stderr
    assert len(unknown.stderr) < 120


def test_each_office_leaf_help_is_bounded_and_single_purpose():
    operations = (
        "info", "get-text", "replace-text", "set-cell", "append-rows",
        "read-table", "read-range", "validate-formulas", "normalize",
        "validate-preservation",
        "ensure-table", "append-table-row", "update-table-row", "outline",
        "read-blocks", "patch",
    )
    for operation in operations:
        output = _help("office", operation)
        assert len(output) <= 2_200, operation
        assert f"agw office {operation}" in output


def test_file_and_run_help_are_progressive_and_compact():
    family = _help("file")
    read = _help("file", "read")
    write = _help("file", "write")
    run = _help("run")
    assert len(family) <= 700
    assert "--content-file" not in family
    assert "--start-line" not in family
    assert "--start-line" in read
    assert "--start-byte" in read
    assert "--max-bytes" in read
    assert "default 32768" in read
    assert "maximum 262144" in read
    assert "usually omit" in read
    assert "--content-file" in write
    assert "--patch" not in write
    assert "--output" in run
    assert "--expected-hash" in run
    assert "root-independent output with recovery" in run
    assert "not an output boundary" in run
    assert len(write) <= 1_000
    assert len(read) <= 900
    assert len(run) <= 800


def test_xlsm_help_discloses_external_workspace_and_preservation_only_where_needed():
    top = _help()
    checkout = _help("checkout")
    publish = _help("publish-file")
    validate = _help("office", "validate-preservation")
    assert "--workspace-dir" not in top
    assert "--workspace-dir" in checkout
    assert "non-synced Guardrails workspace" in checkout
    assert "--preserve-against" in publish
    assert "--expected-preservation-hash" in publish
    assert "--against" in validate
    assert "--expected-original-hash" in validate
    assert len(checkout) <= 900
    assert len(publish) <= 1_400
    assert len(validate) <= 1_000


def test_workflow_help_discloses_trust_details_only_at_the_leaf():
    family = _help("workflow")
    trust = _help("workflow", "trust")
    info = _help("workflow", "info")
    assert "trust" in family and "list" in family and "match" in family and "info" in family
    assert "--expected-manifest-hash" not in family
    assert "--approve-trust" not in family
    assert "--expected-manifest-hash" in trust
    assert "--approve-trust" in trust
    assert "--replace" in trust
    assert "--expected-manifest-hash" not in info
    assert len(family) <= 650
    assert len(trust) <= 1_100
