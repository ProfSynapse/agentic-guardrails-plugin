"""Persisted policy cache: the merged policy document, keyed on file stats.

``engine.load_policy`` reads, parses, validates and merges every policy pack on
every hook call. Nothing about that result changes between calls unless a pack
file or a policy directory changes, so the merged document is kept under
``$AGW_HOME/policy-cache.json`` together with the ``(path, size, st_mtime_ns)``
of every file and the listing of every directory it was built from. A call
whose key matches uses the document as is; anything else (a changed file, a
new pack, a corrupt or foreign cache file, a read error) falls through to a
full parse, which then rewrites the cache.

The cache is an accelerator, never an authority:

* only a HEALTHY result is ever stored, so a DEGRADED or UNAVAILABLE policy is
  re-derived from the real files on every call and can never be masked by a
  stale document;
* the key is captured before the packs are read, so a pack edited during the
  parse cannot be cached under the key of its old contents;
* a cache that cannot be written is simply not written. The caller never sees
  the failure.

This module is deliberately light (os and json only) because the routine Read
path loads it without the rest of the engine.
"""
import json
import os

SCHEMA = "agw.policy-cache/1"
FILE_NAME = "policy-cache.json"
POLICY_SUFFIXES = (".yaml", ".yml", ".json")


def home_path() -> str:
    return os.environ.get("AGW_HOME") or os.path.join(os.path.expanduser("~"), ".agw")


def cache_path(home: str = "") -> str:
    return os.path.join(home or home_path(), FILE_NAME)


def policy_dirs(plugin_root: str, home: str):
    dirs = []
    if plugin_root:
        dirs.append(os.path.join(plugin_root, "policies", "content-rules.d"))
    dirs.append(os.path.join(home, "policies.d"))
    return dirs


def _stat_entry(path: str):
    try:
        st = os.stat(path)
    except OSError:
        return [path, None, None]
    return [path, st.st_size, st.st_mtime_ns]


def _listing(directory: str):
    """Sorted policy-file names, or None when the directory is absent, or
    "unavailable" when it exists but cannot be read (load_policy degrades)."""
    if not os.path.isdir(directory):
        return None
    try:
        return sorted(name for name in os.listdir(directory)
                      if name.lower().endswith(POLICY_SUFFIXES))
    except OSError:
        return "unavailable"


def key(plugin_root: str, home: str) -> dict:
    """Everything load_policy's result depends on, as stats rather than bytes."""
    files = []
    dirs = []
    if plugin_root:
        files.append(_stat_entry(os.path.join(plugin_root, "policies", "core.yaml")))
    for directory in policy_dirs(plugin_root, home):
        names = _listing(directory)
        dirs.append([directory, names])
        if isinstance(names, list):
            files.extend(_stat_entry(os.path.join(directory, name)) for name in names)
    return {"schema": SCHEMA, "plugin_root": plugin_root, "home": home,
            "files": files, "dirs": dirs}


def load(plugin_root: str, home: str, current_key: dict = None):
    """Return the cached policy document when its key matches, else None."""
    path = cache_path(home)
    try:
        with open(path, "rb") as handle:
            cached = json.loads(handle.read().decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(cached, dict) or cached.get("schema") != SCHEMA:
        return None
    document = cached.get("policy")
    if not isinstance(document, dict) or not isinstance(cached.get("key"), dict):
        return None
    if cached["key"] != (current_key or key(plugin_root, home)):
        return None
    return document


def store(home: str, cache_key: dict, document: dict) -> bool:
    """Write the cache atomically. Best effort: a failure here is not an error."""
    path = cache_path(home)
    temp = "%s.%d.tmp" % (path, os.getpid())
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        text = json.dumps({"schema": SCHEMA, "key": cache_key, "policy": document},
                          sort_keys=True)
        with open(temp, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(temp, path)
        return True
    except (OSError, TypeError, ValueError):
        try:
            os.unlink(temp)
        except OSError:
            pass
        return False
