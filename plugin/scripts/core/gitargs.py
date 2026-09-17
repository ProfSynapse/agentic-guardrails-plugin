"""Read a git command line the way git does, for the engine and the planner.

Both the engine's git rules and the pre-image planner need the same two
answers: which subcommand this is once git's own options are skipped, and
which working files it may rewrite. Keeping them here means `git -c k=v
checkout -- file` cannot be a rule for one layer and a bypass for the other.
"""
from __future__ import annotations

from dataclasses import dataclass
import os

# git's own options that take a value and precede the subcommand
# (`git -c core.autocrlf=false commit`, `git -C ../repo checkout`).
GLOBAL_VALUE_OPTIONS = frozenset({
    "-c", "-C", "--git-dir", "--work-tree", "--namespace", "--exec-path",
    "--config-env",
})
# checkout/switch forms that can rewrite tracked files without naming any:
# git only refuses to clobber local edits when none of these is set.
DISCARD_OPTIONS = frozenset({
    "-f", "--force", "--discard-changes", "-m", "--merge", "-p", "--patch",
})
BRANCH_CREATE_OPTIONS = frozenset({"-b", "-B", "--orphan"})
# checkout/switch/restore options whose next token is a value, not a pathspec.
_VALUE_OPTIONS = BRANCH_CREATE_OPTIONS | frozenset({
    "-c", "-C", "-s", "--source", "--pathspec-from-file", "--conflict",
})
_GLOB_CHARS = "*?["

# `TargetList.incomplete_kind` for an unbounded rewrite, so the planner can
# route it to a review instead of the non-waivable pre-image invariant.
UNBOUNDED_KIND = "git-worktree-unbounded"
UNBOUNDED_ASK = ("the set of tracked files it may rewrite cannot be listed "
                 "statically, so no pre-image can be taken")


def subcommand(argv: list) -> tuple[str, list[str]]:
    """Return ``(subcommand, its arguments)`` with git's global options skipped.

    Reading ``argv[1]`` (or the first non-dash token) as the subcommand let
    `git -c k=v checkout -- file` through as a config write.
    """
    index = 1
    while index < len(argv):
        token = str(argv[index])
        if token in GLOBAL_VALUE_OPTIONS:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        return token.lower(), [str(value) for value in argv[index + 1:]]
    return "", []


@dataclass(frozen=True)
class WorktreeScope:
    """What a checkout/switch/restore may rewrite on disk.

    ``files`` are explicit pathspecs that name existing files, relative to the
    working directory or absolute: the planner can take their pre-images.
    ``unbounded`` means some tracked file may be rewritten without being
    named here (a force/merge/discard form, a directory or wildcard
    pathspec); ``reason`` says which.
    """
    files: tuple[str, ...] = ()
    unbounded: bool = False
    reason: str = ""

    @property
    def rewrites(self) -> bool:
        return bool(self.files) or self.unbounded


def _positionals(args: list[str]) -> tuple[list[str], list[str], bool]:
    """Split checkout/switch/restore arguments into options, positionals, and
    whether a `--` separated an explicit pathspec list."""
    options, positionals = [], []
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            return options, args[index + 1:], True
        if token in _VALUE_OPTIONS:
            options.append(token)
            index += 2
            continue
        if token.startswith("-"):
            options.append(token)
            index += 1
            continue
        positionals.append(token)
        index += 1
    return options, positionals, False


def _classify_pathspecs(pathspecs: list[str], cwd: str, *,
                        must_exist: bool) -> WorktreeScope:
    files = []
    for spec in pathspecs:
        if any(char in spec for char in _GLOB_CHARS) or spec.startswith(":"):
            return WorktreeScope(unbounded=True,
                                 reason="a pathspec uses a wildcard or magic prefix")
        path = spec if os.path.isabs(spec) else os.path.join(cwd or "", spec)
        if os.path.isdir(path):
            return WorktreeScope(unbounded=True,
                                 reason="a pathspec names a directory")
        if os.path.isfile(path):
            files.append(spec)
        elif not must_exist:
            # An explicit pathspec for a file that is absent on disk: git will
            # recreate it, and there is nothing to snapshot.
            continue
    return WorktreeScope(files=tuple(files))


def worktree_scope(argv: list, cwd: str = "") -> WorktreeScope:
    """Which working files a git invocation may rewrite (empty for none).

    checkout: `-b`/`-B`/`--orphan` only move HEAD, like `switch -c`, and git
    refuses to clobber local edits, so they rewrite nothing. A `--` pathspec
    list, or a bare argument that names an existing file, is a restore of
    those files (git resolves the same ambiguity by looking on disk). Force,
    merge and patch forms may rewrite any tracked file.
    switch: branch-only; rewrites only with a discard-changes form.
    restore: rewrites its pathspecs unless `--staged` alone is given.
    """
    sub, args = subcommand(argv)
    if sub not in {"checkout", "switch", "restore"}:
        return WorktreeScope()
    options, positionals, explicit = _positionals(args)
    option_set = set(options)
    if sub == "switch":
        if option_set & DISCARD_OPTIONS:
            return WorktreeScope(unbounded=True,
                                 reason="a discard-changes option is set")
        return WorktreeScope()
    if sub == "restore":
        if "--staged" in option_set and not (
                option_set & {"-W", "--worktree"}):
            return WorktreeScope()
        return _classify_pathspecs(positionals, cwd, must_exist=False)
    # checkout
    if option_set & DISCARD_OPTIONS:
        return WorktreeScope(unbounded=True,
                             reason="a force, merge, or patch option is set")
    if explicit:
        return _classify_pathspecs(positionals, cwd, must_exist=False)
    if option_set & BRANCH_CREATE_OPTIONS:
        return WorktreeScope()
    # `git checkout <ref> <path>` restores <path> from <ref>; `git checkout
    # <ref>` alone switches branches. Only arguments that exist on disk count.
    return _classify_pathspecs(positionals, cwd, must_exist=True)


def rewrites_worktree(argv: list, cwd: str = "") -> bool:
    """Whether this git invocation can change tracked files on disk."""
    sub, _args = subcommand(argv)
    if sub in {"clean", "reset"}:
        return True
    return worktree_scope(argv, cwd).rewrites
