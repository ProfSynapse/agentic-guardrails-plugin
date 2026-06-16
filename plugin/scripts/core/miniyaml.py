"""Minimal YAML-subset parser, used only when PyYAML is unavailable.

Supported subset (documented in policies/_README): nested mappings, lists of
scalars and flat mappings, quoted/unquoted scalars, full-line and trailing
comments, inline lists [a, b]. NOT supported: multiline scalars, anchors,
flow mappings. Policy authors must quote any value containing '#' or ': '.

Parse failures raise MiniYamlError; the engine treats that as a degraded
policy pack (fail-closed handling happens in engine.load).
"""
from __future__ import annotations


class MiniYamlError(ValueError):
    pass


def _scalar(text: str):
    text = text.strip()
    if not text or text == "null" or text == "~":
        return None
    if (text.startswith('"') and text.endswith('"')) or \
       (text.startswith("'") and text.endswith("'")):
        return text[1:-1]
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        return [_scalar(p) for p in _split_inline(inner)] if inner else []
    low = text.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text


def _split_inline(inner: str):
    parts, depth, cur, quote = [], 0, "", ""
    for ch in inner:
        if quote:
            cur += ch
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
            cur += ch
        elif ch == "[":
            depth += 1
            cur += ch
        elif ch == "]":
            depth -= 1
            cur += ch
        elif ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return parts


def _strip_comment(line: str) -> str:
    out, quote = "", ""
    for i, ch in enumerate(line):
        if quote:
            out += ch
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
            out += ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        else:
            out += ch
    return out.rstrip()


def loads(text: str):
    lines = []
    for raw in text.splitlines():
        stripped = _strip_comment(raw)
        if stripped.strip():
            indent = len(stripped) - len(stripped.lstrip())
            lines.append((indent, stripped.strip()))
    value, idx = _parse_block(lines, 0, lines[0][0] if lines else 0)
    if idx != len(lines):
        raise MiniYamlError(f"trailing content at line index {idx}")
    return value


def _parse_block(lines, idx, indent):
    if idx >= len(lines):
        return None, idx
    if lines[idx][1].startswith("- "):
        return _parse_list(lines, idx, indent)
    return _parse_map(lines, idx, indent)


def _parse_map(lines, idx, indent):
    result = {}
    while idx < len(lines):
        ind, content = lines[idx]
        if ind < indent:
            break
        if ind > indent:
            raise MiniYamlError(f"unexpected indent: {content!r}")
        if content.startswith("- "):
            break
        if ":" not in content:
            raise MiniYamlError(f"expected 'key: value': {content!r}")
        key, _, rest = content.partition(":")
        key = key.strip().strip('"').strip("'")
        rest = rest.strip()
        if rest:
            result[key] = _scalar(rest)
            idx += 1
        else:
            idx += 1
            if idx < len(lines) and lines[idx][0] > indent:
                result[key], idx = _parse_block(lines, idx, lines[idx][0])
            else:
                result[key] = None
    return result, idx


def _parse_list(lines, idx, indent):
    result = []
    while idx < len(lines):
        ind, content = lines[idx]
        if ind != indent or not content.startswith("- "):
            if ind >= indent and not content.startswith("- "):
                break
            if ind < indent:
                break
        item_text = content[2:].strip()
        if ":" in item_text and not item_text.startswith(("'", '"', "[")):
            # list item is an inline-start mapping; gather continuation keys
            sub = [(indent + 2, item_text)]
            idx += 1
            while idx < len(lines) and lines[idx][0] > indent:
                sub.append(lines[idx])
                idx += 1
            value, consumed = _parse_map(sub, 0, indent + 2)
            if consumed != len(sub):
                raise MiniYamlError("bad mapping inside list item")
            result.append(value)
        else:
            result.append(_scalar(item_text))
            idx += 1
    return result, idx
