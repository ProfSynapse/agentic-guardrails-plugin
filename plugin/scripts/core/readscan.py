"""Filename and content checks for reading a file: the read-side primitives.

Reading a credential-type file is often legitimate (dev setup), so it asks;
the only hard deny (credential file + network tool in one command) lives in
the engine's exec rules. These functions are what the engine's READ path runs
per file, kept in a module that imports only os and re so the routine-Read
fast path (core.readfast) can run the very same checks without loading the
engine. core.engine re-exports every name here.
"""
import os
import re

_SECRET_BASENAME_RE = re.compile(
    r"^(?:\.env(?:\..+)?|\.netrc|\.pgpass|\.git-credentials"
    r"|id_(?:rsa|dsa|ecdsa|ed25519)|.*\.(?:pem|key|p12|pfx|jks|keystore|ppk))$",
    re.IGNORECASE)
_SECRET_NAMES = {"credentials", "credentials.json", "service_account.json",
                 "service-account.json", "secrets.json", "secrets.yaml", "secrets.yml"}
_SECRET_DIRS = {".ssh", ".aws", ".azure", ".kube", "gcloud"}
_NOT_SECRET_SUFFIX = re.compile(r"\.(?:example|sample|template|dist|pub)$", re.IGNORECASE)

_PRESCAN_BYTES = 64 * 1024
_PRESCAN_MARKERS = (
    ("a private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), True),
    ("an AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), True),
    ("an API token", re.compile(
        r"\bgh[pos]_[A-Za-z0-9]{20,}|\bsk-[A-Za-z0-9_-]{20,}"
        r"|\bxox[bpoars]-[A-Za-z0-9-]{10,}"), True),
    ("a hardcoded password", re.compile(
        r"(?i)\b(?:password|passwd|pwd)\s*[=:]\s*[\"'][^\"']{6,}[\"']"), True),
    ("a credential assignment", re.compile(
        r"(?mi)^[A-Za-z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_?KEY)[A-Za-z0-9_]*"
        r"\s*=\s*(?:[\"'][^\"']{6,}[\"']|[A-Za-z0-9_./+=:-]{6,})\s*$"), True),
    ("a confidentiality marking", re.compile(
        r"(?i)\b(?:confidential|do not distribute|internal use only|trade secret)\b"), False),
    ("embedded prompt-injection instructions", re.compile(
        r"\b(?:ignore|disregard|forget)\b[^.\n]{0,40}"
        r"\b(?:instructions|prompt|rules|guidance|directives)\b"
        r"|\b(?:say|claim|pretend|tell them)\b[^.\n]{0,30}"
        r"\b(?:already\s+)?approved\b", re.IGNORECASE), False),
)

_DEV_SOURCE_SUFFIXES = {
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".sh", ".ps1", ".psm1",
    ".rb", ".go", ".rs", ".java", ".c", ".cc", ".cpp", ".h", ".hpp",
}
_DEV_DOC_BASENAMES = {
    "readme.md", "research.md", "plan.md", "testing.md", "releasing.md",
    "contributing.md", "codex.md", "deployment.md", "agents.md",
}


def _is_low_confidence_context(path: str) -> bool:
    normalized = os.path.abspath(path).replace("\\", "/").lower()
    parts = [part for part in normalized.split("/") if part]
    base = parts[-1] if parts else ""
    suffix = os.path.splitext(base)[1]
    return (suffix in _DEV_SOURCE_SUFFIXES or suffix in {".log", ".jsonl"}
            or base in _DEV_DOC_BASENAMES
            or any(part in {"test", "tests", "docs", "plans"} for part in parts))


def _is_secret_path(path: str) -> bool:
    if "://" in path:
        return False  # URL, not a filesystem path
    p = os.path.expanduser(path).replace("\\", "/")
    base = os.path.basename(p)
    if _NOT_SECRET_SUFFIX.search(base):
        return False
    if _SECRET_BASENAME_RE.match(base) or base.lower() in _SECRET_NAMES:
        return True
    return any(d in p.split("/")[:-1] for d in _SECRET_DIRS)


def _prescan_file(path: str):
    """Return a human label for the first secret/confidential marker found in
    the file head, or None. Cheap (one bounded read), binary-safe."""
    if _NOT_SECRET_SUFFIX.search(os.path.basename(path)):
        return None  # .example/.sample/.template files hold placeholders
    try:
        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            return None
        with open(path, "rb") as f:
            head = f.read(_PRESCAN_BYTES)
    except OSError:
        return None
    if b"\0" in head:
        return None  # binary container; plaintext markers won't be meaningful
    text = head.decode("utf-8", "replace")
    # A contextual hit (a confidentiality marking, injection-shaped prose) in
    # a source file is discarded downstream as low confidence, so for the
    # dev-source suffixes the two contextual markers are not run at all. The
    # five hard markers (private key, AKIA, tokens, password and credential
    # assignments) always scan, whatever the file is called.
    skip_contextual = os.path.splitext(path)[1].lower() in _DEV_SOURCE_SUFFIXES
    for label, rx, high_confidence in _PRESCAN_MARKERS:
        if skip_contextual and not high_confidence:
            continue
        if rx.search(text):
            contextual_low = not high_confidence and _is_low_confidence_context(path)
            return label, contextual_low
    return None
