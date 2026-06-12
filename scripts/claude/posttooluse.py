#!/usr/bin/env python3
"""Claude PostToolUse adapter: audit-log completed tool calls. Never blocks."""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))


def main():
    payload = json.load(sys.stdin)
    from core import auditlog
    ti = payload.get("tool_input") or {}
    auditlog.log("posttooluse", {
        "tool": payload.get("tool_name", ""),
        "command": ti.get("command", ""),
        "paths": [p for p in [ti.get("file_path", "")] if p],
        "session": payload.get("session_id", ""),
        "ok": not payload.get("tool_error"),
    })


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
