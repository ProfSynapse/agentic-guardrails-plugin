"""Audit logging with secret redaction. Append-only JSONL at $AGW_HOME/audit.jsonl."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime

from . import store

# Secret-format patterns, reused for both audit redaction and (via policy)
# content rules. Conservative: better to over-redact a log line than leak.
REDACTION_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                                   # AWS access key
    re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S+"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),  # JWT
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/-]{16,}"),
    re.compile(r"ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}"),
    re.compile(r"sk-[A-Za-z0-9-]{20,}"),                               # API secret keys
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),                       # Slack tokens
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*['\"]?[^\s'\"]{8,}"),
]


def redact(text: str) -> str:
    if not text:
        return text
    for pattern in REDACTION_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def log(event_name: str, record: dict):
    record = dict(record)
    record["event"] = event_name
    record["ts"] = datetime.now().isoformat(timespec="seconds")
    record["schema_version"] = store.SCHEMA_VERSION
    for key in ("command", "content", "reason", "detail"):
        if isinstance(record.get(key), str):
            record[key] = redact(record[key])
    path = os.path.join(store.agw_home(), "audit.jsonl")
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass  # auditing must never break the agent


def tail(n: int = 50) -> list:
    path = os.path.join(store.agw_home(), "audit.jsonl")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()[-n:]
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
