"""The routine-Read fast path: say nothing, exactly when the engine would.

A benign Read of an ordinary file is the commonest hook call and its full
path (engine, events, the policy loader) is most of its cost. For a Read the
engine's answer is DEFER (no output) unless one of a handful of checks fires:
the policy is not HEALTHY, a path rule zones the file, the file looks like a
cloud placeholder, its name is credential-shaped, or its head carries a
secret or sensitive marker. ``routine_read`` runs those same checks, with the
engine's own functions and the persisted policy, and answers True only when
every one of them is clear. Any other situation, including "not sure", is a
False, and the adapter takes the full path, which then produces the real
decision. The fast path can therefore only ever shorten a call whose answer
is silence; it cannot change a decision.
"""
import os
import stat as stat_mod
import sys

from . import policycache
from .readscan import _is_secret_path, _prescan_file


def _may_be_placeholder(path: str) -> bool:
    """True when profiles.is_placeholder could say yes for this file.

    Mirrors its stat logic; the one inference it corroborates with a folder
    profile (st_blocks == 0 on POSIX) is left to the engine by answering True.
    """
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    if st.st_size == 0:
        return False
    if sys.platform == "win32":
        attrs = getattr(st, "st_file_attributes", 0)
        recall = getattr(stat_mod, "FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS", 0x00400000)
        offline = getattr(stat_mod, "FILE_ATTRIBUTE_OFFLINE", 0x00001000)
        return bool(attrs & (recall | offline))
    blocks = getattr(st, "st_blocks", None)
    if blocks is None:
        return False
    if sys.platform == "darwin":
        dataless = getattr(stat_mod, "SF_DATALESS", 0x40000000)
        if getattr(st, "st_flags", 0) & dataless:
            return True
    return blocks == 0


def routine_read(file_path, plugin_root: str) -> bool:
    """True only when the engine's READ evaluation would be a silent DEFER."""
    if not isinstance(file_path, str):
        return False
    document = policycache.load(plugin_root, policycache.home_path())
    if document is None:
        # No HEALTHY cached policy: the full loader decides (and caches).
        return False
    if document.get("path_rules"):
        # Zoned paths are the engine's call.
        return False
    path = os.path.abspath(os.path.expanduser(file_path))
    if _may_be_placeholder(path):
        return False
    if _is_secret_path(path):
        return False
    if _prescan_file(path) is not None:
        return False
    return True
