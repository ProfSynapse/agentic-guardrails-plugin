"""Conservative PowerShell parameter binding for local mutation cmdlets.

The static metadata below mirrors ``Get-Command``/``CommandMetadata`` for the
supported commands.  It intentionally models only literal command lines; any
runtime-dependent binding is reported as incomplete so prestate enforcement
can fail closed.
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
        frozenset(_COMMON_VALUES | {"path", "literalpath", "itemtype", "value"}),
        {"literalpath": "path"},
    ),
}

_ALIASES = {
    alias: canonical
    for canonical, spec in _SPECS.items()
    for alias in spec.aliases
}


@dataclass
class BindingResult:
    recognized: bool = False
    complete: bool = True
    targets: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    append: bool = False
    reason: str = ""


def _incomplete(reason: str) -> BindingResult:
    return BindingResult(recognized=True, complete=False, reason=reason)


def _literal(token: str) -> bool:
    if token is None or token in {"SUBST_OUT", "--%"}:
        return False
    # These shapes require runtime evaluation or represent PowerShell arrays,
    # expressions, script blocks, splatting, or variable expansion.
    return not any(char in token for char in "`$@{}[](),;|&")


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
        if token.startswith("@") or "$" in token:
            return _incomplete("PowerShell dynamic values or splatting prevent safe target binding")
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
                    return _incomplete(f"PowerShell parameter '-{raw}' is missing its value")
                attached = args[i + 1]
                i += 2
            else:
                i += 1
            if not _literal(attached):
                return _incomplete(
                    f"PowerShell parameter '-{raw}' does not have a static literal value"
                )
            role = spec.role_aliases.get(parameter, parameter)
            if role in named and named[role] != attached:
                return _incomplete(f"PowerShell parameter '{role}' is specified more than once")
            named[role] = attached
            continue
        if not _literal(token):
            return _incomplete("PowerShell positional binding contains a dynamic expression")
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
            return _incomplete(f"PowerShell command did not identify a literal {role}")
        targets.append(value)

    result = BindingResult(recognized=True, targets=targets,
                           append="append" in switches)
    if canonical in {"copy-item", "move-item"}:
        source = bound.get("path")
        if not source:
            return _incomplete("PowerShell command did not identify a literal source path")
        result.sources.append(source)
    return result
