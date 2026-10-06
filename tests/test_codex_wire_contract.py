"""Regression for the native deny-bypassed-by-extra-field incident."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from codex_wire_contract import SCHEMA, validate_wire
from test_codex_adapter import PRE, REPO, run_hook


@pytest.mark.parametrize('bad', [
    {'agwRefusal': {}},
    {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny', 'agwRefusal': {}}},
    {'hookSpecificOutput': {'permissionDecision': 'deny'}},
    {'hookSpecificOutput': {'hookEventName': 'PostToolUse'}},
    {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'defer'}},
    {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecisionReason': None}},
    {'continue': 1},
    {'systemMessage': {}},
])
def test_captured_contract_rejects_invalid_responses(bad):
    with pytest.raises(AssertionError):
        validate_wire(bad)


@pytest.mark.parametrize('payload', [
    {'tool_name': 'Bash', 'tool_input': {'command': 'rm -rf /tmp/not-executed'}},
    {'tool_name': 'exec_command', 'tool_input': {'cmd': 'rm -rf /tmp/not-executed'}},
    {'tool_name': 'apply_patch', 'tool_input': {'patch': '*** Begin Patch\n*** Delete File: /tmp/not-executed\n*** End Patch\n'}},
    {'tool_name': 'mcp__fixture__send_email', 'tool_input': {'recipient': 'nobody@example.invalid', 'body': 'wire test'}},
    {'tool_name': 'unknown_wire_test', 'tool_input': {}},
])
def test_real_adapter_denials_conform(payload, tmp_path):
    output = run_hook(dict(payload, cwd=str(tmp_path), session_id='wire-regression'))
    validate_wire(output)
    assert output['hookSpecificOutput']['permissionDecision'] == 'deny'


@pytest.mark.parametrize('raw', ['{', 'null', '[]'])
def test_real_adapter_malformed_input_fail_closed_schema(raw, tmp_path):
    result = subprocess.run([sys.executable, PRE], input=raw, text=True,
                            capture_output=True, timeout=30,
                            env=dict(os.environ, PLUGIN_ROOT=REPO,
                                     AGW_HOME=str(tmp_path / 'store')))
    assert result.returncode == 0
    output = json.loads(result.stdout)
    validate_wire(output)
    assert output['hookSpecificOutput']['permissionDecision'] == 'deny'


def test_wire_fixture_matches_native_pinned_schema_when_available():
    # Optional: point AGW_CODEX_PINNED_BINARY at the exact Codex 0.160.0
    # Linux x86_64 binary to prove the captured fixture is the embedded schema.
    configured = os.environ.get('AGW_CODEX_PINNED_BINARY', '')
    binary = Path(configured) if configured else None
    if binary is None or not binary.is_file():
        pytest.skip('optional pinned native Codex binary not configured')
    import hashlib
    import mmap
    with binary.open('rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == '12eb3e81114588aca3b7998f4f19e8997b056aca08e57a7ca7c8a3ec8c652aad'
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            marker = data.find(b'"PreToolUseHookSpecificOutputWire": {')
            assert marker >= 0
            start = data.rfind(b'{\n  "$schema"', max(0, marker - 12000), marker)
            assert start >= 0
            native, _ = json.JSONDecoder().raw_decode(data[start:start + 20000].decode('utf-8', 'replace'))
    assert native == SCHEMA

