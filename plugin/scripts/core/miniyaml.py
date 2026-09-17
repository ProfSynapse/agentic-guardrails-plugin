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


def _closes_cleanly(text: str) -> bool:
    """True when `text` is one flow collection that opens and closes exactly once.

    Used only for a scalar that already starts with a flow indicator. Depth must
    never go negative, must not return to zero before the final character
    (``[a] [b]`` is two values, not one), and must be zero at the end. A quote
    left open inside makes the whole thing unreadable, so that fails too.
    """
    depth, quote = 0, ""
    for index, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
            if depth < 0:
                return False
            if depth == 0 and index != len(text) - 1:
                return False
    return depth == 0 and not quote


def _scalar(text: str):
    text = text.strip()
    if not text or text == "null" or text == "~":
        return None
    # Fail closed on the shapes PyYAML rejects. This parser is the *only* policy
    # reader when PyYAML is absent - the documented primary mode - so anything it
    # silently accepts as a plain string is a corrupt pack loading as HEALTHY.
    if text[0] in "\"'":
        if len(text) < 2 or text[-1] != text[0]:
            raise MiniYamlError(f"unterminated quoted scalar: {text!r}")
        return text[1:-1]
    if text[0] in "]}":
        raise MiniYamlError(f"unexpected {text[0]!r} with no opening bracket")
    if text[0] == "{":
        # Flow mappings are outside the documented subset; accepting one as a
        # plain string would hide a real mapping from every rule matcher.
        raise MiniYamlError(f"flow mappings are not supported: {text!r}")
    if text[0] == "[":
        if not _closes_cleanly(text):
            raise MiniYamlError(f"unbalanced inline list: {text!r}")
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
    for number, raw in enumerate(text.splitlines(), 1):
        stripped = _strip_comment(raw)
        if stripped.strip():
            # YAML forbids tabs in indentation, and this parser measures nesting
            # in columns: one tab would silently reparent a whole block.
            if "\t" in raw[:len(raw) - len(raw.lstrip())]:
                raise MiniYamlError(f"tab used as indentation on line {number}")
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
