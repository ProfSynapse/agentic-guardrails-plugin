"""Narrow argparse schema projection used by ``agw schema``."""
from __future__ import annotations

import argparse


class SchemaLookupError(ValueError):
    error_code = "schema_command_not_found"


def _subcommands(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    return {}


def resolve(parser: argparse.ArgumentParser, command_path: list[str]) -> argparse.ArgumentParser:
    current = parser
    traversed = []
    for name in command_path:
        choices = _subcommands(current)
        if name not in choices:
            raise SchemaLookupError(
                "unknown command path: " + " ".join([*traversed, name])
            )
        current = choices[name]
        traversed.append(name)
    return current


def _type_name(value) -> str:
    if value is None:
        return "string"
    return getattr(value, "__name__", str(value))


def project(parser: argparse.ArgumentParser, command_path: list[str]) -> dict:
    target = resolve(parser, command_path)
    arguments = []
    for action in target._actions:
        if action.dest in {"help", "json"}:
            continue
        item = {
            "name": action.dest,
            "positional": not bool(action.option_strings),
            "options": list(action.option_strings),
            "required": bool(getattr(action, "required", False)),
            "nargs": action.nargs,
            "type": _type_name(getattr(action, "type", None)),
            "help": action.help or "",
        }
        if action.choices is not None:
            item["choices"] = list(action.choices)
        if action.default is not None and action.default != argparse.SUPPRESS:
            item["default"] = action.default
        arguments.append(item)
    return {
        "schema": "agw-command-schema/v1",
        "command": ["agw", *command_path],
        "description": target.description or "",
        "arguments": arguments,
        "subcommands": sorted(_subcommands(target)),
    }
