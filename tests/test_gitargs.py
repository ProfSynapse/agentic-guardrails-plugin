"""git argv reading shared by the engine rules and the pre-image planner."""
from core import gitargs


def test_subcommand_skips_gits_own_options():
    assert gitargs.subcommand(["git", "checkout", "-b", "x"]) == ("checkout", ["-b", "x"])
    assert gitargs.subcommand(
        ["git", "-c", "core.autocrlf=false", "checkout", "--", "f"]
    ) == ("checkout", ["--", "f"])
    assert gitargs.subcommand(["git", "-C", "../repo", "--no-pager", "log"]) == ("log", [])
    assert gitargs.subcommand(["git"]) == ("", [])
    assert gitargs.subcommand(["git", "-c"]) == ("", [])


def test_branch_operations_rewrite_nothing(tmp_path):
    cwd = str(tmp_path)
    for argv in (
        ["git", "checkout", "-b", "x"],
        ["git", "checkout", "-B", "x", "origin/main"],
        ["git", "checkout", "--orphan", "gh-pages"],
        ["git", "checkout", "main"],
        ["git", "switch", "-c", "x"],
        ["git", "switch", "main"],
        ["git", "restore", "--staged", "f.py"],
        ["git", "commit", "-m", "x"],
    ):
        scope = gitargs.worktree_scope(argv, cwd)
        assert not scope.rewrites, argv
        assert not gitargs.rewrites_worktree(argv, cwd), argv


def test_named_files_are_the_scope(tmp_path):
    (tmp_path / "f.py").write_text("x\n", encoding="utf-8")
    cwd = str(tmp_path)
    assert gitargs.worktree_scope(["git", "checkout", "--", "f.py"], cwd).files == ("f.py",)
    assert gitargs.worktree_scope(["git", "checkout", "f.py"], cwd).files == ("f.py",)
    assert gitargs.worktree_scope(["git", "checkout", "main", "f.py"], cwd).files == ("f.py",)
    assert gitargs.worktree_scope(["git", "restore", "f.py"], cwd).files == ("f.py",)
    assert gitargs.worktree_scope(
        ["git", "restore", "--source", "HEAD~1", "f.py"], cwd).files == ("f.py",)
    # An explicit pathspec for a file that is not on disk has nothing to lose.
    assert not gitargs.worktree_scope(["git", "checkout", "--", "gone.py"], cwd).rewrites
    # A bare name that is not on disk is a ref, exactly as git reads it.
    assert not gitargs.worktree_scope(["git", "checkout", "gone.py"], cwd).rewrites


def test_unbounded_forms_name_their_reason(tmp_path):
    (tmp_path / "src").mkdir()
    cwd = str(tmp_path)
    for argv, fragment in (
        (["git", "checkout", "-f", "main"], "force"),
        (["git", "checkout", "--merge", "main"], "force"),
        (["git", "checkout", "-p"], "force"),
        (["git", "switch", "--discard-changes", "main"], "discard"),
        (["git", "switch", "-m", "main"], "discard"),
        (["git", "checkout", "--", "src"], "directory"),
        (["git", "checkout", "src"], "directory"),
        (["git", "checkout", "--", "*.py"], "wildcard"),
        (["git", "restore", ":/"], "wildcard"),
    ):
        scope = gitargs.worktree_scope(argv, cwd)
        assert scope.unbounded and not scope.files, argv
        assert fragment in scope.reason, argv
        assert gitargs.rewrites_worktree(argv, cwd), argv


def test_clean_and_reset_always_count_as_rewrites(tmp_path):
    assert gitargs.rewrites_worktree(["git", "clean", "-fd"], str(tmp_path))
    assert gitargs.rewrites_worktree(["git", "reset", "--hard"], str(tmp_path))
    assert not gitargs.worktree_scope(["git", "reset", "--hard"], str(tmp_path)).rewrites
