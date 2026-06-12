#!/usr/bin/env python3
"""Claude SessionStart adapter: bootstrap the store, warm caches, and inject
the agw vocabulary as context (skill auto-trigger is fallible; this is not)."""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.environ.get("CLAUDE_PLUGIN_ROOT") or os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, os.path.dirname(_HERE))

CONTEXT = """agentic-guardrails is active in this session. File-safety rules:
- Deletion (`rm` etc.) is disabled. Use `agw archive <path>` (reversible via \
`agw restore <path>`); `agw undo` reverts the last operation.
- To modify Office/proprietary documents, use the CRUA flow: `agw checkout <file>` \
(creates an editable markdown/csv working copy in _workspace/), edit the working \
copy, then `agw publish <file>` (archives the old version and replaces the original).
- Cloud-synced folders (OneDrive/SharePoint/Google Drive/Dropbox): run `agw scan \
<folder>` before bulk work; never edit cloud-only placeholder files or .gdoc stubs.
- `agw status` shows open checkouts; `agw doctor` checks the environment.
Every file the native Write/Edit tools touch is automatically snapshotted first — \
prior versions are always recoverable."""


def main():
    try:
        from core import engine, store
        store.agw_home()  # ensures ~/.agw exists
        engine.load_policy(PLUGIN_ROOT)  # warms any future cache; validates packs
    except Exception:
        pass
    json.dump({"hookSpecificOutput": {
        "hookEventName": "SessionStart",
        "additionalContext": CONTEXT}}, sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
