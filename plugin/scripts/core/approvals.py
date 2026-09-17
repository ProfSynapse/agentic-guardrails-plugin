"""Approval providers and short-lived exact-event prompt de-duplication."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
import sys
import threading
import time

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes
else:
    # Off Windows nothing here can open a dialog, and `ctypes` plus
    # `ctypes.wintypes` cost ~2 ms of the per-call hook budget on every
    # platform. The Win32 ABI below is therefore built on first touch - by
    # `_ensure_win32_abi()` inside the functions that need it, or by the module
    # `__getattr__` at the bottom, which is how the Linux CI tests that assert
    # the exact struct layout still reach `approvals.TASKDIALOGCONFIG`.
    ctypes = None
    wintypes = None

from .decisions import GuardrailDecision, LOW, PromptRequest


@dataclass(frozen=True)
class ApprovalResponse:
    # Kept permissive at construction for backward compatibility with callers
    # crossing this boundary. Authorization itself is deliberately strict:
    # neither truthy values nor unknown outcomes can authorize an action.
    approved: object
    outcome: object
    diagnostic: str = ""

    def is_valid(self) -> bool:
        if (type(self.approved) is not bool or type(self.outcome) is not str
                or type(self.diagnostic) is not str):
            return False
        if self.approved:
            return self.outcome == "approved"
        return self.outcome in {
            "denied", "cancelled", "headless-deny", "provider-unavailable",
            "provider-error", "not-prompt-eligible", "invalid-response",
            "policy-revision-unavailable", "prompt-incomplete",
        }

    def authorizes(self) -> bool:
        return self.is_valid() and self.approved is True and self.outcome == "approved"


def _validated(response) -> ApprovalResponse:
    if isinstance(response, ApprovalResponse) and response.is_valid():
        return response
    return ApprovalResponse(False, "invalid-response", "validation:invalid-response")


_WIN32_ABI_NAMES = frozenset({
    "ACTCTXW", "TASKDIALOG_BUTTON", "_TASKDIALOG_MAIN_ICON",
    "_TASKDIALOG_FOOTER_ICON", "_CALLBACK_FACTORY", "PFTASKDIALOGCALLBACK",
    "TASKDIALOGCONFIG", "ULONG_PTR", "INVALID_HANDLE_VALUE",
})


def _ensure_win32_abi():
    """Define the Win32 TaskDialog ABI, importing ctypes on the first ask.

    Idempotent. Windows runs it at import; everywhere else it runs only when a
    caller (or a test) actually reaches for one of these names, so the ordinary
    hook path never pays for ctypes on a platform that cannot show a dialog.
    """
    global ctypes, wintypes
    global ACTCTXW, TASKDIALOG_BUTTON, _TASKDIALOG_MAIN_ICON
    global _TASKDIALOG_FOOTER_ICON, _CALLBACK_FACTORY, PFTASKDIALOGCALLBACK
    global TASKDIALOGCONFIG, ULONG_PTR, INVALID_HANDLE_VALUE
    if "TASKDIALOGCONFIG" in globals():
        return
    if ctypes is None:
        import ctypes as _ctypes
        from ctypes import wintypes as _wintypes
        ctypes, wintypes = _ctypes, _wintypes

    class ACTCTXW(ctypes.Structure):
        _fields_ = [
            # Windows ULONG/DWORD are fixed 32-bit values. ctypes.wintypes maps
            # them through host c_ulong, which is 64-bit on many Unix runners.
            ("cbSize", ctypes.c_uint32),
            ("dwFlags", ctypes.c_uint32),
            ("lpSource", wintypes.LPCWSTR),
            ("wProcessorArchitecture", wintypes.USHORT),
            ("wLangId", wintypes.WORD),
            ("lpAssemblyDirectory", wintypes.LPCWSTR),
            ("lpResourceName", wintypes.LPCWSTR),
            ("lpApplicationName", wintypes.LPCWSTR),
            ("hModule", wintypes.HMODULE),
        ]


    class TASKDIALOG_BUTTON(ctypes.Structure):
        # CommCtrl.h wraps the task-dialog declarations in pshpack1.h.
        _pack_ = 1
        _fields_ = [("nButtonID", ctypes.c_int),
                    ("pszButtonText", wintypes.LPCWSTR)]


    class _TASKDIALOG_MAIN_ICON(ctypes.Union):
        _fields_ = [("hMainIcon", wintypes.HICON),
                    ("pszMainIcon", wintypes.LPCWSTR)]


    class _TASKDIALOG_FOOTER_ICON(ctypes.Union):
        _fields_ = [("hFooterIcon", wintypes.HICON),
                    ("pszFooterIcon", wintypes.LPCWSTR)]


    _CALLBACK_FACTORY = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)
    PFTASKDIALOGCALLBACK = _CALLBACK_FACTORY(
        ctypes.c_long, wintypes.HWND, wintypes.UINT, wintypes.WPARAM,
        wintypes.LPARAM, ctypes.c_ssize_t,
    )


    class TASKDIALOGCONFIG(ctypes.Structure):
        # CommCtrl.h uses anonymous unions and one-byte packing for this ABI.
        _pack_ = 1
        _anonymous_ = ("main_icon", "footer_icon")
        _fields_ = [
            ("cbSize", wintypes.UINT), ("hwndParent", wintypes.HWND),
            ("hInstance", wintypes.HINSTANCE), ("dwFlags", wintypes.UINT),
            ("dwCommonButtons", wintypes.UINT),
            ("pszWindowTitle", wintypes.LPCWSTR),
            ("main_icon", _TASKDIALOG_MAIN_ICON),
            ("pszMainInstruction", wintypes.LPCWSTR),
            ("pszContent", wintypes.LPCWSTR), ("cButtons", wintypes.UINT),
            ("pButtons", ctypes.POINTER(TASKDIALOG_BUTTON)),
            ("nDefaultButton", ctypes.c_int), ("cRadioButtons", wintypes.UINT),
            ("pRadioButtons", ctypes.c_void_p), ("nDefaultRadioButton", ctypes.c_int),
            ("pszVerificationText", wintypes.LPCWSTR),
            ("pszExpandedInformation", wintypes.LPCWSTR),
            ("pszExpandedControlText", wintypes.LPCWSTR),
            ("pszCollapsedControlText", wintypes.LPCWSTR),
            ("footer_icon", _TASKDIALOG_FOOTER_ICON),
            ("pszFooter", wintypes.LPCWSTR),
            ("pfCallback", PFTASKDIALOGCALLBACK),
            ("lpCallbackData", ctypes.c_ssize_t),
            ("cxWidth", wintypes.UINT),
        ]


    ULONG_PTR = ctypes.c_size_t
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def __getattr__(name):
    # Only reached for names not already in the module dict, so this fires once
    # per Win32 ABI name and never for anything defined eagerly.
    if name in _WIN32_ABI_NAMES:
        _ensure_win32_abi()
        return globals()[name]
    raise AttributeError("module %r has no attribute %r" % (__name__, name))


if sys.platform == "win32":
    _ensure_win32_abi()
TDF_ALLOW_DIALOG_CANCELLATION = 0x0008
_COMMON_CONTROLS_MANIFEST = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "common-controls-v6.manifest"
)


class _NativeUIFailure(RuntimeError):
    def __init__(self, diagnostic: str):
        super().__init__(diagnostic)
        self.diagnostic = diagnostic


def _last_error() -> int:
    _ensure_win32_abi()
    getter = getattr(ctypes, "get_last_error", None)
    return int(getter() if getter else 0)


def _exception_diagnostic(stage: str, exc: BaseException) -> str:
    return f"native-ui:{stage}:exception:{type(exc).__name__}"


def _configure_activation_apis(kernel32):
    _ensure_win32_abi()
    kernel32.CreateActCtxW.argtypes = [ctypes.POINTER(ACTCTXW)]
    kernel32.CreateActCtxW.restype = wintypes.HANDLE
    kernel32.ActivateActCtx.argtypes = [wintypes.HANDLE, ctypes.POINTER(ULONG_PTR)]
    kernel32.ActivateActCtx.restype = wintypes.BOOL
    kernel32.DeactivateActCtx.argtypes = [wintypes.DWORD, ULONG_PTR]
    kernel32.DeactivateActCtx.restype = wintypes.BOOL
    kernel32.ReleaseActCtx.argtypes = [wintypes.HANDLE]
    kernel32.ReleaseActCtx.restype = None
    return kernel32


def _configure_task_dialog_api(comctl32):
    _ensure_win32_abi()
    comctl32.TaskDialogIndirect.argtypes = [
        ctypes.POINTER(TASKDIALOGCONFIG), ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int), ctypes.POINTER(wintypes.BOOL),
    ]
    comctl32.TaskDialogIndirect.restype = ctypes.c_long
    return comctl32


def _load_kernel32():
    _ensure_win32_abi()
    return _configure_activation_apis(
        ctypes.WinDLL("kernel32", use_last_error=True)
    )


def _load_task_dialog():
    _ensure_win32_abi()
    # Load comctl32 only after the v6 activation context is active.
    return _configure_task_dialog_api(
        ctypes.WinDLL("comctl32", use_last_error=True)
    )


def _handle_value(handle):
    return getattr(handle, "value", handle)


def _config_problem(config, buttons) -> str:
    """Return a machine-readable local config defect without invoking UI."""
    _ensure_win32_abi()
    if config.cbSize != ctypes.sizeof(TASKDIALOGCONFIG):
        return "cbsize"
    if config.cButtons != len(buttons):
        return "button-count"
    if config.cButtons and not bool(config.pButtons):
        return "button-pointer"
    button_ids = {button.nButtonID for button in buttons}
    if len(button_ids) != len(buttons) or any(button_id <= 0 for button_id in button_ids):
        return "button-id"
    if config.nDefaultButton not in button_ids:
        return "default-button"
    if any(not button.pszButtonText for button in buttons):
        return "button-text"
    if not config.pszMainInstruction:
        return "main-instruction"
    if not config.pszContent:
        return "content"
    return ""


def _default_button_id(request: PromptRequest, allow_id: int, cancel_id: int) -> int:
    """Map the reviewed recommendation to the native dialog's focused button."""
    return allow_id if request.default_choice == "allow" else cancel_id


@contextmanager
def _common_controls_v6(kernel32):
    _ensure_win32_abi()
    if not os.path.isfile(_COMMON_CONTROLS_MANIFEST):
        raise _NativeUIFailure("native-ui:manifest:missing")
    actctx = ACTCTXW()
    actctx.cbSize = ctypes.sizeof(ACTCTXW)
    actctx.lpSource = _COMMON_CONTROLS_MANIFEST
    handle = kernel32.CreateActCtxW(ctypes.byref(actctx))
    if _handle_value(handle) in (None, INVALID_HANDLE_VALUE):
        raise _NativeUIFailure(f"native-ui:create-actctx:last-error:{_last_error()}")
    cookie = ULONG_PTR()
    if not kernel32.ActivateActCtx(handle, ctypes.byref(cookie)):
        error = _last_error()
        kernel32.ReleaseActCtx(handle)
        raise _NativeUIFailure(f"native-ui:activate-actctx:last-error:{error}")
    try:
        yield
    finally:
        deactivated = kernel32.DeactivateActCtx(0, cookie)
        error = _last_error() if not deactivated else 0
        kernel32.ReleaseActCtx(handle)
        if not deactivated:
            raise _NativeUIFailure(
                f"native-ui:deactivate-actctx:last-error:{error}"
            )


class ApprovalProvider:
    def request(self, request: PromptRequest) -> ApprovalResponse:
        raise NotImplementedError


class NativeUIInTestError(BaseException):
    """Hard test tripwire that normal provider fail-closed handling cannot hide."""


class HeadlessApprovalProvider(ApprovalProvider):
    """Deterministic non-interactive provider. It always chooses safety."""

    def request(self, request: PromptRequest) -> ApprovalResponse:
        return ApprovalResponse(False, "headless-deny")


class NativeApprovalProvider(ApprovalProvider):
    """Windows UI boundary. No other module may initialize native dialogs."""

    ALLOW_ID = 100
    CANCEL_ID = 101

    def __init__(self, timeout_s: int = 100):
        if os.environ.get("AGW_TEST_MODE") == "1" or os.environ.get("PYTEST_CURRENT_TEST"):
            # Deliberately derives from BaseException so broad production
            # ``except Exception`` fail-closed wrappers cannot mask a test bug.
            raise NativeUIInTestError("native approval UI initialized during a test")
        # Deprecated compatibility parameter. Approval dialogs intentionally
        # have no automatic timeout: only an explicit user choice closes them.
        _ = timeout_s

    def request(self, request: PromptRequest) -> ApprovalResponse:
        prompt_problem = request.validation_problem()
        if prompt_problem:
            return ApprovalResponse(
                False, "prompt-incomplete", "validation:" + prompt_problem
            )
        if os.name != "nt":
            return ApprovalResponse(False, "provider-unavailable", "platform:not-windows")
        try:
            return _validated(self._task_dialog(request))
        except _NativeUIFailure as exc:
            return ApprovalResponse(False, "provider-error", exc.diagnostic)
        except Exception as exc:
            return ApprovalResponse(
                False, "provider-error", _exception_diagnostic("request", exc)
            )

    def _task_dialog(self, request: PromptRequest) -> ApprovalResponse:
        _ensure_win32_abi()
        prompt_problem = request.validation_problem()
        if prompt_problem:
            return ApprovalResponse(
                False, "prompt-incomplete", "validation:" + prompt_problem
            )
        buttons = (TASKDIALOG_BUTTON * 2)(
            TASKDIALOG_BUTTON(self.ALLOW_ID, request.allow_label),
            TASKDIALOG_BUTTON(self.CANCEL_ID, request.cancel_label),
        )
        config = TASKDIALOGCONFIG()
        config.cbSize = ctypes.sizeof(TASKDIALOGCONFIG)
        config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION
        config.pszWindowTitle = request.title
        config.pszMainInstruction = request.action
        config.pszContent = request.primary_text()
        config.cButtons = 2
        config.pButtons = buttons
        config.nDefaultButton = _default_button_id(
            request, self.ALLOW_ID, self.CANCEL_ID
        )
        problem = _config_problem(config, buttons)
        if problem:
            return ApprovalResponse(
                False, "provider-error", f"native-ui:config:{problem}"
            )
        chosen = ctypes.c_int(self.CANCEL_ID)
        kernel32 = _load_kernel32()
        with _common_controls_v6(kernel32):
            comctl32 = _load_task_dialog()
            hr = comctl32.TaskDialogIndirect(
                ctypes.byref(config), ctypes.byref(chosen), None, None)
        if hr != 0:
            return ApprovalResponse(
                False, "provider-error",
                f"native-ui:task-dialog:hresult:0x{int(hr) & 0xffffffff:08x}",
            )
        if chosen.value == self.ALLOW_ID:
            return ApprovalResponse(True, "approved")
        return ApprovalResponse(False, "cancelled")


_CACHE: dict[tuple[str, str, str], tuple[float, ApprovalResponse]] = {}
_CACHE_LOCK = threading.Lock()
DEDUPE_SECONDS = 30


def request_approval(decision: GuardrailDecision, request: PromptRequest,
                     provider: ApprovalProvider) -> ApprovalResponse:
    """Request approval, coalescing only an identical host event and operation."""
    if not decision.prompt_eligible or decision.confidence == LOW:
        return ApprovalResponse(False, "not-prompt-eligible")
    prompt_problem = request.validation_problem()
    if prompt_problem:
        return ApprovalResponse(
            False, "prompt-incomplete", "validation:" + prompt_problem
        )
    if not decision.policy_revision or request.policy_revision != decision.policy_revision:
        return ApprovalResponse(False, "policy-revision-unavailable")

    # Without a host identity there is no safe proof that two calls are the same
    # event, so intentionally skip de-duplication.
    key = ((request.event_id, request.operation_fingerprint, request.policy_revision)
           if request.event_id else None)
    now = time.monotonic()
    if key:
        with _CACHE_LOCK:
            cached = _CACHE.get(key)
            if cached and now - cached[0] <= DEDUPE_SECONDS:
                return cached[1]
    try:
        response = _validated(provider.request(request))
    except Exception as exc:
        response = ApprovalResponse(
            False, "provider-error", _exception_diagnostic("provider", exc)
        )
    if key:
        with _CACHE_LOCK:
            _CACHE[key] = (now, response)
            expired = [item for item, value in _CACHE.items()
                       if now - value[0] > DEDUPE_SECONDS]
            for item in expired:
                _CACHE.pop(item, None)
    return response


# The pending-approval handshake lives in core.pending_approvals so the
# PostToolUse adapters can check it before loading anything heavier than
# os/json/hashlib. Re-exported here for every existing caller.
from .pending_approvals import (  # noqa: E402,F401
    PENDING_SECONDS, _host_event_id, _identity_hash, _pending_path,
    approval_identity, consume_pending_approval, record_pending_approval,
)


def default_provider(timeout_s: int = 100) -> ApprovalProvider:
    if os.environ.get("AGW_APPROVAL_PROVIDER", "").lower() == "headless":
        return HeadlessApprovalProvider()
    return NativeApprovalProvider(timeout_s)
