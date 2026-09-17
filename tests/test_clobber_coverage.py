"""What the exec path counts as a mutation, and what it snapshots first."""
import json
import os
import subprocess
import sys

import pytest

from core import engine

REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "plugin")
DISPATCH = os.path.join(REPO, "scripts", "claude", "_dispatch.py")


def run_hook(command, project, agw_home, tool="Bash"):
    payload = {"tool_name": tool, "tool_input": {"command": command},
               "cwd": project, "session_id": "clobber-coverage",
               "hook_event_name": "PreToolUse"}
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=REPO, AGW_HOME=agw_home)
    result = subprocess.run(
        [sys.executable, DISPATCH, "pretooluse"], input=json.dumps(payload),
        capture_output=True, text=True, env=env, cwd=project, timeout=60,
    )
    assert result.returncode == 0, f"hook crashed: {result.stderr}"
    if not result.stdout.strip():
        return "allow", ""
    out = json.loads(result.stdout).get("hookSpecificOutput") or {}
    action = out.get("permissionDecision", "allow")
    return ("allow" if action == "defer" else action,
            out.get("permissionDecisionReason", ""))


@pytest.fixture()
def project(tmp_path):
    for name in ("notes.txt", "out.txt", "patterns.txt", "archive.tar"):
        (tmp_path / name).write_text("x\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.txt").write_text("a\n", encoding="utf-8")
    (tmp_path / "dst").mkdir()
    return str(tmp_path)


# --- posix -rf as indirect-command evidence ---------------------------------

@pytest.mark.parametrize("command", [
    "$RM -rf ~/My-Documents",
    "$RM -fr ~/My-Documents",
    "$deleter -Rf ~/work",
    "$tool -rfv ~/work",
])
def test_an_indirect_command_with_rf_is_a_mutation(command, project, agw_home):
    action, reason = run_hook(command, project, agw_home)
    assert action == "deny", reason
    assert "builtin:indirect-mutation" in reason


def test_an_indirect_command_without_force_flags_is_still_allowed(project,
                                                                 agw_home):
    action, reason = run_hook("$LS -la", project, agw_home)
    assert action == "allow", reason


@pytest.mark.parametrize("command", [
    # `-rf` here means "read patterns from a file" and "append to an archive".
    # The heads are known and read-only, so nothing may be snapshotted.
    "grep -rf patterns.txt .",
    "tar -rf archive.tar notes.txt",
])
def test_rf_on_a_read_only_head_schedules_no_pre_image(command, project,
                                                       agw_home):
    targets = engine.clobber_targets(command, project, include_absent=True)
    assert list(targets) == []
    action, reason = run_hook(command, project, agw_home)
    assert action == "allow", reason


# --- xcopy / robocopy destinations ------------------------------------------

def test_xcopy_schedules_a_pre_image_for_its_destination(project):
    targets = engine.clobber_targets("xcopy notes.txt out.txt /Y", project,
                                     dialect="powershell")
    assert list(targets) == [os.path.join(project, "out.txt")]


def test_an_xcopy_switch_is_not_read_as_the_destination(project):
    targets = engine.clobber_targets("xcopy notes.txt out.txt /Y /I /E", project,
                                     dialect="powershell")
    assert list(targets) == [os.path.join(project, "out.txt")]


def test_xcopy_into_a_directory_names_the_file_it_replaces(project):
    with open(os.path.join(project, "dst", "notes.txt"), "w",
              encoding="utf-8") as handle:
        handle.write("old\n")
    targets = engine.clobber_targets("xcopy notes.txt dst /Y", project,
                                     dialect="powershell")
    assert list(targets) == [os.path.join(project, "dst", "notes.txt")]


def test_robocopy_schedules_a_pre_image_for_the_destination_it_replaces(project):
    """`robocopy src dst` clobbers `dst/a.txt`, which is what gets snapshotted.

    The destination *directory* is deliberately not the target: a directory has
    no pre-image, so naming it would fail the snapshot step and deny every
    routine copy instead of protecting anything.
    """
    with open(os.path.join(project, "dst", "a.txt"), "w",
              encoding="utf-8") as handle:
        handle.write("old\n")
    targets = engine.clobber_targets("robocopy src dst /E", project,
                                     dialect="powershell")
    assert list(targets) == [os.path.join(project, "dst", "a.txt")]


def test_a_robocopy_switch_is_not_read_as_a_positional(project):
    """`_CMD_SWITCH_RE` matches one letter, so `/MIR` had to be filtered by `/`."""
    with open(os.path.join(project, "dst", "a.txt"), "w",
              encoding="utf-8") as handle:
        handle.write("old\n")
    for command in ("robocopy /NP src dst", "robocopy src dst /MIR /NP"):
        targets = engine.clobber_targets(command, project, dialect="powershell")
        assert list(targets) == [os.path.join(project, "dst", "a.txt")], command


def test_robocopy_named_files_narrow_the_destination_set(project):
    with open(os.path.join(project, "dst", "a.txt"), "w",
              encoding="utf-8") as handle:
        handle.write("old\n")
    with open(os.path.join(project, "dst", "b.txt"), "w",
              encoding="utf-8") as handle:
        handle.write("old\n")
    targets = engine.clobber_targets("robocopy src dst a.txt", project,
                                     dialect="powershell")
    assert list(targets) == [os.path.join(project, "dst", "a.txt")]


def test_a_dynamic_bulk_copy_destination_is_incomplete(project):
    targets = engine.clobber_targets("robocopy src $dest /E", project,
                                     include_absent=True, dialect="powershell")
    assert targets.complete is False


def test_the_hook_still_allows_a_plain_bulk_copy(project, agw_home):
    with open(os.path.join(project, "dst", "a.txt"), "w",
              encoding="utf-8") as handle:
        handle.write("old\n")
    action, reason = run_hook("robocopy src dst /E", project, agw_home,
                              tool="PowerShell")
    assert action == "allow", reason
    archived = []
    for base, _dirs, files in os.walk(os.path.join(agw_home, "archive")):
        archived.extend(files)
    assert any(name.endswith("a.txt") for name in archived), archived


# --- the site-extended regenerable set --------------------------------------

@pytest.fixture()
def site_regenerable(agw_home):
    """A drop-in policy pack that calls `.custom-cache` regenerable."""
    policies = os.path.join(agw_home, "policies.d")
    os.makedirs(policies, exist_ok=True)
    with open(os.path.join(policies, "site.yaml"), "w", encoding="utf-8") as fh:
        fh.write("version: 1\nsettings:\n  regenerable_globs:\n"
                 "    - .custom-cache\n")
    return agw_home


@pytest.fixture()
def cache_project(tmp_path):
    work = tmp_path / "work"
    (work / ".custom-cache").mkdir(parents=True)
    (work / ".custom-cache" / "a").write_text("1\n", encoding="utf-8")
    return str(work)


def test_the_planner_honours_a_site_regenerable_tree(site_regenerable,
                                                     cache_project):
    """Without the set threaded through, the planner asks for a pre-image.

    The engine already ALLOWs the delete under `builtin:rm-regenerable`, so the
    only thing left to fail is the pre-image step — an invariant DENY on a
    command policy says is fine.
    """
    from core import mutations
    from core.events import ToolEvent, EXEC

    policy = engine.load_policy(REPO)
    cfg = engine.resolve_settings(policy)
    assert ".custom-cache" in cfg["regenerable"]
    event = ToolEvent(kind=EXEC, tool="Bash", command="rm -rf .custom-cache",
                      cwd=cache_project)

    without = mutations.plan([event], engine.clobber_targets, plugin_root=REPO)
    assert without.complete is False

    threaded = mutations.plan([event], engine.clobber_targets, plugin_root=REPO,
                              regenerable=cfg["regenerable"])
    assert threaded.complete is True
    assert threaded.targets == []
    assert any(reason == engine.SKIP_REGENERABLE
               for _target, reason in threaded.skipped)


def test_the_hook_allows_a_site_regenerable_delete(site_regenerable,
                                                   cache_project):
    action, reason = run_hook("rm -rf .custom-cache", cache_project,
                              site_regenerable)
    assert action == "allow", reason


def test_a_non_regenerable_delete_is_untouched(site_regenerable, cache_project):
    with open(os.path.join(cache_project, "keep.txt"), "w",
              encoding="utf-8") as handle:
        handle.write("keep\n")
    action, _ = run_hook("rm -rf keep.txt", cache_project, site_regenerable)
    assert action == "deny"
