"""Import a module the first time it is used, not the first time it is named.

The hook adapters name a dozen ``core`` modules up front but a routine Read or
MCP call touches three of them. The rest (``store``, ``mutations``,
``preimages``, ``presentation``, ``approvals``) drag in the archive store,
workflows and half the standard library, and only matter once an event mutates
files or a decision needs a prompt. ``LazyModule`` lets the adapter body keep
its plain ``store.session_approved(...)`` spelling while the import happens at
that call, inside the same try/except that turns any failure into an ASK.
"""
import importlib


class LazyModule:
    """Proxy that imports ``name`` on first attribute access."""

    __slots__ = ("_name", "_module")

    def __init__(self, name):
        self._name = name
        self._module = None

    def __getattr__(self, attr):
        module = self._module
        if module is None:
            module = importlib.import_module(self._name)
            self._module = module
        return getattr(module, attr)

    def __repr__(self):
        state = "loaded" if self._module is not None else "deferred"
        return "<LazyModule %s (%s)>" % (self._name, state)
