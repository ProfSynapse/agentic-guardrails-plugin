"""Conservative PowerShell parameter binding for local mutation cmdlets.

The static metadata below mirrors ``Get-Command``/``CommandMetadata`` for the
supported commands.  It intentionally models only literal command lines; any
runtime-dependent binding is reported as incomplete so prestate enforcement
can fail closed.

An incomplete binding also carries a ``kind``.  ``UNRESOLVED_PATH`` means the
cmdlet is recognized but its path cannot be read without running the command
(splatting, a variable, a here-string); that is a question for the user, and a
caller should route it to a waivable ASK rather than a non-waivable invariant.
``UNSUPPORTED_SHAPE`` means the command line is outside this binder's model at
all, and stays fail-closed.
"""
from __future__ import annotations

from dataclasses import dataclass, field


_COMMON_SWITCHES = {
    "confirm", "debug", "force", "passthru", "recurse", "verbose", "whatif",
    "usetransaction",
}
_COMMON_VALUES = {
    "credential", "erroraction", "errorvariable", "exclude", "filter",
    "include", "informationaction", "informationvariable", "outbuffer",
    "outvariable", "pipelinevariable", "warningaction", "warningvariable",
}


@dataclass(frozen=True)
class CommandSpec:
    aliases: frozenset[str]
    positional: tuple[str, ...]
    path_roles: frozenset[str]
    switches: frozenset[str]
    values: frozenset[str]
    role_aliases: dict[str, str] = field(default_factory=dict)

    @property
    def parameters(self) -> frozenset[str]:
        return self.switches | self.values


_SPECS = {
    "set-content": CommandSpec(
        frozenset({"set-content", "sc"}),
        ("path", "value"), frozenset({"path"}),
        frozenset(_COMMON_SWITCHES | {"nonewline"}),
        frozenset(_COMMON_VALUES | {"path", "literalpath", "value", "encoding", "stream"}),
        {"literalpath": "path"},
    ),
    "out-file": CommandSpec(
        frozenset({"out-file"}),
        ("filepath", "encoding"), frozenset({"filepath"}),
        frozenset(_COMMON_SWITCHES | {"append", "noclobber", "nonewline"}),
        frozenset(_COMMON_VALUES | {"filepath", "literalpath", "encoding", "width",
                                    "inputobject"}),
        {"literalpath": "filepath"},
    ),
    "copy-item": CommandSpec(
        frozenset({"copy-item", "copy", "cp", "cpi"}),
        ("path", "destination"), frozenset({"destination"}),
        frozenset(_COMMON_SWITCHES | {"container"}),
        frozenset(_COMMON_VALUES | {"path", "literalpath", "destination",
                                    "fromsession", "tosession"}),
        {"literalpath": "path"},
    ),
    "move-item": CommandSpec(
        frozenset({"move-item", "mi", "move", "mv"}),
        ("path", "destination"), frozenset({"destination"}),
        frozenset(_COMMON_SWITCHES),
        frozenset(_COMMON_VALUES | {"path", "literalpath", "destination"}),
        {"literalpath": "path"},
    ),
    "remove-item": CommandSpec(
        frozenset({"remove-item", "del", "erase", "rd", "ri", "rm", "rmdir"}),
        ("path",), frozenset({"path"}),
        frozenset(_COMMON_SWITCHES),
        frozenset(_COMMON_VALUES | {"path", "literalpath", "stream"}),
        {"literalpath": "path"},
    ),
    "new-item": CommandSpec(
        frozenset({"new-item", "mkdir", "md", "ni"}),
        ("path",), frozenset({"path"}),
        frozenset(_COMMON_SWITCHES),
        frozenset(_COMMON_VALUES | {
            "path", "literalpath", "itemtype", "value", "target",
        }),
        {"literalpath": "path"},
    ),
}

_ALIASES = {
    alias: canonical
    for canonical, spec in _SPECS.items()
    for alias in spec.aliases
}


# Why a binding is incomplete.
#
# ``UNRESOLVED_PATH``: a recognized mutation cmdlet whose path simply cannot be
# read without running it — splatting (``Set-Content @params``), a variable, a
# here-string body. Nothing about it says the operation is dangerous, only that
# guardrails cannot name the file, so it is a question for the user and belongs
# at a standard-level ASK rather than a non-waivable invariant.
#
# ``UNSUPPORTED_SHAPE``: the command line itself is outside what this binder
# models (stop-parsing, an unknown parameter, a duplicated role). That stays
# fail-closed, because we cannot even say which cmdlet would run.
UNRESOLVED_PATH = "unresolved-path"
UNSUPPORTED_SHAPE = "unsupported-shape"

# The single line a caller should show the user for an UNRESOLVED_PATH result.
UNRESOLVED_PATH_ASK = ("path could not be statically resolved; "
                       "approve to proceed")


@dataclass
class BindingResult:
    recognized: bool = False
    complete: bool = True
    targets: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    append: bool = False
    reason: str = ""
    kind: str = ""

    @property
    def askable(self) -> bool:
        """Whether this failure is a question for the user, not an invariant."""
        return (self.recognized and not self.complete
                and self.kind == UNRESOLVED_PATH)


def _incomplete(reason: str, kind: str = UNSUPPORTED_SHAPE) -> BindingResult:
    return BindingResult(recognized=True, complete=False, reason=reason,
                         kind=kind)


def _unresolved(reason: str) -> BindingResult:
    return _incomplete(reason, UNRESOLVED_PATH)


def _literal(token: str) -> bool:
    if token is None or token in {"SUBST_OUT", "--%"}:
        return False
    # These shapes require runtime evaluation or represent PowerShell arrays,
    # expressions, script blocks, splatting, or variable expansion.
    return not any(char in token for char in "`$@{}[](),;|&*?")


def _resolve_parameter(name: str, spec: CommandSpec):
    lowered = name.lower()
    if lowered in spec.parameters:
        return lowered
    matches = sorted(param for param in spec.parameters if param.startswith(lowered))
    return matches[0] if len(matches) == 1 else None


def bind(argv: list[str], dialect: str) -> BindingResult:
    """Bind one literal PowerShell mutation command.

    Aliases are recognized only in the PowerShell dialect.  Unknown commands
    return ``recognized=False`` so POSIX/cmd handling remains independent.
    """
    if dialect != "powershell" or not argv:
        return BindingResult()
    name = argv[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    if name.endswith(".exe"):
        name = name[:-4]
    canonical = _ALIASES.get(name)
    if not canonical:
        return BindingResult()
    spec = _SPECS[canonical]

    named: dict[str, str] = {}
    switches = set()
    positionals = []
    args = list(argv[1:])
    i = 0
    while i < len(args):
        token = args[i]
        if token == "--%":
            return _incomplete("PowerShell stop-parsing prevents safe target binding")
        if token.startswith("-") and token != "-":
            raw = token[1:]
            attached = None
            if ":" in raw:
                raw, attached = raw.split(":", 1)
            parameter = _resolve_parameter(raw, spec)
            if parameter is None:
                return _incomplete(
                    f"PowerShell parameter '-{raw}' is unknown or ambiguous"
                )
            if parameter in spec.switches:
                if attached is not None and attached.lower() not in {"true", "false", "$true", "$false"}:
                    return _incomplete(
                        f"PowerShell switch '-{raw}' has a dynamic value"
                    )
                switches.add(parameter)
                i += 1
                continue
            if attached is None:
                if i + 1 >= len(args) or args[i + 1].startswith("-"):
                    return _unresolved(
                        f"PowerShell parameter '-{raw}' is missing its value"
                    )
                attached = args[i + 1]
                i += 2
            else:
                i += 1
            role = spec.role_aliases.get(parameter, parameter)
            if role in named and named[role] != attached:
                return _incomplete(f"PowerShell parameter '{role}' is specified more than once")
            named[role] = attached
            continue
        positionals.append(token)
        i += 1

    bound = dict(named)
    remaining_roles = [role for role in spec.positional if role not in bound]
    if len(positionals) > len(remaining_roles):
        return _incomplete("PowerShell command has extra positional arguments")
    for role, value in zip(remaining_roles, positionals):
        bound[role] = value

    targets = []
    for role in spec.path_roles:
        value = bound.get(role)
        if not value:
            return _unresolved(
                f"PowerShell command did not identify a literal {role}"
            )
        if not _literal(value):
            return _unresolved(
                f"PowerShell {role} does not have a static literal value"
            )
        targets.append(value)

    result = BindingResult(recognized=True, targets=targets,
                           append="append" in switches)
    if canonical in {"copy-item", "move-item"}:
        source = bound.get("path")
        if not source or not _literal(source):
            return _unresolved(
                "PowerShell source path uses a dynamic value or wildcard"
            )
        result.sources.append(source)
    if canonical == "new-item" and str(bound.get("itemtype", "")).lower() in {
            "symboliclink", "junction"}:
        source = bound.get("target")
        if not source or not _literal(source):
            return _unresolved(
                "PowerShell link creation did not identify a literal target path"
            )
        result.sources.append(source)
    return result
