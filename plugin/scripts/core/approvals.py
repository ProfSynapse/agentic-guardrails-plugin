"""Approval providers and short-lived exact-event prompt de-duplication."""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import hashlib
import json
import os
import threading
import time

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
            "policy-revision-unavailable",
        }

    def authorizes(self) -> bool:
        return self.is_valid() and self.approved is True and self.outcome == "approved"


def _validated(response) -> ApprovalResponse:
    if isinstance(response, ApprovalResponse) and response.is_valid():
        return response
    return ApprovalResponse(False, "invalid-response", "validation:invalid-response")


class ACTCTXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.ULONG),
        ("dwFlags", wintypes.DWORD),
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
TDF_ALLOW_DIALOG_CANCELLATION = 0x0008
_COMMON_CONTROLS_MANIFEST = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "common-controls-v6.manifest"
)


class _NativeUIFailure(RuntimeError):
    def __init__(self, diagnostic: str):
        super().__init__(diagnostic)
        self.diagnostic = diagnostic


def _last_error() -> int:
    getter = getattr(ctypes, "get_last_error", None)
    return int(getter() if getter else 0)


def _exception_diagnostic(stage: str, exc: BaseException) -> str:
    return f"native-ui:{stage}:exception:{type(exc).__name__}"


def _configure_activation_apis(kernel32):
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
    comctl32.TaskDialogIndirect.argtypes = [
        ctypes.POINTER(TASKDIALOGCONFIG), ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int), ctypes.POINTER(wintypes.BOOL),
    ]
    comctl32.TaskDialogIndirect.restype = ctypes.c_long
    return comctl32


def _load_kernel32():
    return _configure_activation_apis(
        ctypes.WinDLL("kernel32", use_last_error=True)
    )


def _load_task_dialog():
    # Load comctl32 only after the v6 activation context is active.
    return _configure_task_dialog_api(
        ctypes.WinDLL("comctl32", use_last_error=True)
    )


def _handle_value(handle):
    return getattr(handle, "value", handle)


def _config_problem(config, buttons) -> str:
    """Return a machine-readable local config defect without invoking UI."""
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


@contextmanager
def _common_controls_v6(kernel32):
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
        config.nDefaultButton = self.CANCEL_ID
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


PENDING_SECONDS = 120


def _host_event_id(payload: dict) -> str:
    return str(payload.get("event_id") or payload.get("invocation_id") or
               payload.get("tool_use_id") or "")


def _identity_hash(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()


def approval_identity(memo_key: str, policy_revision: str) -> str:
    """One-way, revision-bound identity for a resource approval."""
    material = f"agw-pending-approval-v1\0{policy_revision}\0{memo_key}"
    return _identity_hash(material)


def _pending_path(payload: dict, session_id: str) -> str:
    event_id = _host_event_id(payload)
    if not event_id or not session_id:
        return ""
    home = os.environ.get("AGW_HOME") or os.path.join(os.path.expanduser("~"), ".agw")
    directory = os.path.join(home, "pending-approvals")
    os.makedirs(directory, exist_ok=True)
    key = _identity_hash(f"{session_id}\0{event_id}")
    return os.path.join(directory, key + ".json")


def record_pending_approval(payload: dict, session_id: str, memo_key: str,
                            policy_revision: str, operation_fingerprint: str) -> bool:
    """Persist a privacy-minimal pre-hook candidate for one post-hook consume."""
    path = _pending_path(payload, session_id)
    if not path or not memo_key or not policy_revision or not operation_fingerprint:
        return False
    record = {
        "session_hash": _identity_hash(session_id),
        "event_hash": _identity_hash(_host_event_id(payload)),
        "approval_identity": approval_identity(memo_key, policy_revision),
        "policy_revision": policy_revision,
        "operation_fingerprint": operation_fingerprint,
        "created_at": time.time(),
    }
    temp = path + f".{os.getpid()}.{threading.get_ident()}.tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(record, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)
    return True


def consume_pending_approval(payload: dict, session_id: str):
    """Atomically consume one matching, unexpired pending approval record."""
    path = _pending_path(payload, session_id)
    if not path or not os.path.exists(path):
        return None
    consuming = path + f".{os.getpid()}.{threading.get_ident()}.consuming"
    try:
        os.replace(path, consuming)
    except OSError:
        return None
    try:
        with open(consuming, encoding="utf-8") as handle:
            record = json.load(handle)
        if time.time() - float(record.get("created_at", 0)) > PENDING_SECONDS:
            return None
        if record.get("session_hash") != _identity_hash(session_id):
            return None
        if record.get("event_hash") != _identity_hash(_host_event_id(payload)):
            return None
        if not record.get("policy_revision") or not record.get("approval_identity"):
            return None
        return record
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None
    finally:
        try:
            os.unlink(consuming)
        except OSError:
            pass


def default_provider(timeout_s: int = 100) -> ApprovalProvider:
    if os.environ.get("AGW_APPROVAL_PROVIDER", "").lower() == "headless":
        return HeadlessApprovalProvider()
    return NativeApprovalProvider(timeout_s)
