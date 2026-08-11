"""Noninteractive tests for the Windows TaskDialog activation boundary."""
import ctypes
import os
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from core import approvals
from core.decisions import PromptRequest


class FakeFunction:
    def __init__(self, implementation=lambda *_args: 1):
        self.implementation = implementation
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.implementation(*args)


class FakeKernel32:
    def __init__(self, create=123, activate=True, deactivate=True):
        self.calls = []

        def create_actctx(pointer):
            value = ctypes.cast(
                pointer, ctypes.POINTER(approvals.ACTCTXW)
            ).contents
            self.calls.append(("create", value.cbSize, value.lpSource))
            return create

        def activate_actctx(handle, cookie_pointer):
            self.calls.append(("activate", handle))
            ctypes.cast(
                cookie_pointer, ctypes.POINTER(approvals.ULONG_PTR)
            ).contents.value = 456
            return activate

        def deactivate_actctx(flags, cookie):
            self.calls.append(("deactivate", flags, cookie.value))
            return deactivate

        def release_actctx(handle):
            self.calls.append(("release", handle))

        self.CreateActCtxW = FakeFunction(create_actctx)
        self.ActivateActCtx = FakeFunction(activate_actctx)
        self.DeactivateActCtx = FakeFunction(deactivate_actctx)
        self.ReleaseActCtx = FakeFunction(release_actctx)


class FakeComctl32:
    def __init__(self, chosen, hresult=0):
        self.seen = {}

        def task_dialog(config_pointer, chosen_pointer, _radio, _verification):
            config = ctypes.cast(
                config_pointer, ctypes.POINTER(approvals.TASKDIALOGCONFIG)
            ).contents
            self.seen = {
                "title": config.pszWindowTitle,
                "instruction": config.pszMainInstruction,
                "content": config.pszContent,
                "default": config.nDefaultButton,
                "flags": config.dwFlags,
                "buttons": tuple(
                    config.pButtons[index].pszButtonText
                    for index in range(config.cButtons)
                ),
            }
            ctypes.cast(
                chosen_pointer, ctypes.POINTER(ctypes.c_int)
            ).contents.value = chosen
            return hresult

        self.TaskDialogIndirect = FakeFunction(task_dialog)


def _request():
    return PromptRequest(
        title="Agent safety check",
        action="The agent wants to read a potentially sensitive file.",
        targets=("customer.env",),
        reason="The file may contain private information.",
        consequence="Its contents may enter the agent's work.",
        safeguard="Guardrails does not create a recovery copy for this action.",
        event_id="event", operation_fingerprint="fingerprint",
        policy_revision="revision",
    )


def _provider():
    return object.__new__(approvals.NativeApprovalProvider)


def test_common_controls_manifest_is_valid_v6_dependency():
    path = Path(approvals._COMMON_CONTROLS_MANIFEST)
    assert path.is_file()
    root = ET.fromstring(path.read_text(encoding="utf-8"))
    text = ET.tostring(root, encoding="unicode")
    assert "Microsoft.Windows.Common-Controls" in text
    assert 'version="6.0.0.0"' in text


def test_native_api_signatures_are_explicit():
    kernel = approvals._configure_activation_apis(FakeKernel32())
    dialog = approvals._configure_task_dialog_api(FakeComctl32(101))
    for name in ("CreateActCtxW", "ActivateActCtx", "DeactivateActCtx",
                 "ReleaseActCtx"):
        function = getattr(kernel, name)
        assert function.argtypes is not None
        assert hasattr(function, "restype")
    assert dialog.TaskDialogIndirect.argtypes is not None
    assert dialog.TaskDialogIndirect.restype is ctypes.c_long


def test_ctypes_layout_matches_windows_sdk_reference():
    """Expected values come from MSVC x64/x86 CommCtrl.h and winbase.h ABI."""
    pointer_size = ctypes.sizeof(ctypes.c_void_p)
    if pointer_size == 8:
        expected_button = (12, {"nButtonID": 0, "pszButtonText": 4})
        expected_config = (160, {
            "cbSize": 0, "hwndParent": 4, "hInstance": 12,
            "dwFlags": 20, "dwCommonButtons": 24, "pszWindowTitle": 28,
            "main_icon": 36, "pszMainInstruction": 44, "pszContent": 52,
            "cButtons": 60, "pButtons": 64, "nDefaultButton": 72,
            "cRadioButtons": 76, "pRadioButtons": 80,
            "nDefaultRadioButton": 88, "pszVerificationText": 92,
            "pszExpandedInformation": 100, "pszExpandedControlText": 108,
            "pszCollapsedControlText": 116, "footer_icon": 124,
            "pszFooter": 132, "pfCallback": 140, "lpCallbackData": 148,
            "cxWidth": 156,
        })
        expected_actctx = (56, {
            "cbSize": 0, "dwFlags": 4, "lpSource": 8,
            "wProcessorArchitecture": 16, "wLangId": 18,
            "lpAssemblyDirectory": 24, "lpResourceName": 32,
            "lpApplicationName": 40, "hModule": 48,
        })
    else:
        expected_button = (8, {"nButtonID": 0, "pszButtonText": 4})
        expected_config = (96, {
            "cbSize": 0, "hwndParent": 4, "hInstance": 8,
            "dwFlags": 12, "dwCommonButtons": 16, "pszWindowTitle": 20,
            "main_icon": 24, "pszMainInstruction": 28, "pszContent": 32,
            "cButtons": 36, "pButtons": 40, "nDefaultButton": 44,
            "cRadioButtons": 48, "pRadioButtons": 52,
            "nDefaultRadioButton": 56, "pszVerificationText": 60,
            "pszExpandedInformation": 64, "pszExpandedControlText": 68,
            "pszCollapsedControlText": 72, "footer_icon": 76,
            "pszFooter": 80, "pfCallback": 84, "lpCallbackData": 88,
            "cxWidth": 92,
        })
        expected_actctx = (32, {
            "cbSize": 0, "dwFlags": 4, "lpSource": 8,
            "wProcessorArchitecture": 12, "wLangId": 14,
            "lpAssemblyDirectory": 16, "lpResourceName": 20,
            "lpApplicationName": 24, "hModule": 28,
        })

    for structure, (size, offsets) in (
        (approvals.TASKDIALOG_BUTTON, expected_button),
        (approvals.TASKDIALOGCONFIG, expected_config),
        (approvals.ACTCTXW, expected_actctx),
    ):
        assert ctypes.sizeof(structure) == size
        assert {name: getattr(structure, name).offset for name in offsets} == offsets


def test_config_probe_distinguishes_invalid_fields_without_ui():
    buttons = (approvals.TASKDIALOG_BUTTON * 2)(
        approvals.TASKDIALOG_BUTTON(100, "Allow once"),
        approvals.TASKDIALOG_BUTTON(101, "Cancel"),
    )
    config = approvals.TASKDIALOGCONFIG()
    config.cbSize = ctypes.sizeof(approvals.TASKDIALOGCONFIG)
    config.pszMainInstruction = "Review this operation."
    config.pszContent = "Why we're asking: Review is required."
    config.cButtons = 2
    config.pButtons = buttons
    config.nDefaultButton = 101
    assert approvals._config_problem(config, buttons) == ""
    config.nDefaultButton = 999
    assert approvals._config_problem(config, buttons) == "default-button"
    config.nDefaultButton = 101
    config.cbSize = 0
    assert approvals._config_problem(config, buttons) == "cbsize"


@pytest.mark.skipif(os.name != "nt", reason="native activation probe is Windows-only")
def test_real_activation_context_and_taskdialog_api_probe_is_noninteractive():
    kernel = approvals._load_kernel32()
    with approvals._common_controls_v6(kernel):
        dialog = approvals._load_task_dialog()
        assert dialog.TaskDialogIndirect.argtypes is not None
        assert dialog.TaskDialogIndirect.restype is ctypes.c_long


def test_activation_context_wraps_dialog_and_releases(monkeypatch):
    kernel = FakeKernel32()
    dialog = FakeComctl32(approvals.NativeApprovalProvider.ALLOW_ID)
    monkeypatch.setattr(approvals, "_load_kernel32", lambda: kernel)
    monkeypatch.setattr(approvals, "_load_task_dialog", lambda: dialog)
    response = _provider()._task_dialog(_request())
    assert response == approvals.ApprovalResponse(True, "approved")
    assert [call[0] for call in kernel.calls] == [
        "create", "activate", "deactivate", "release"
    ]
    assert dialog.seen["instruction"] == _request().action
    assert _request().action not in dialog.seen["content"]
    assert dialog.seen["default"] == approvals.NativeApprovalProvider.CANCEL_ID
    assert dialog.seen["buttons"] == ("Allow once", "Cancel (recommended)")


@pytest.mark.parametrize("chosen", [
    approvals.NativeApprovalProvider.CANCEL_ID,
    0,  # Escape/window close can return no custom button identifier.
    2,  # IDCANCEL from the native cancellation path.
])
def test_cancel_escape_and_close_are_cancelled(monkeypatch, chosen):
    kernel = FakeKernel32()
    monkeypatch.setattr(approvals, "_load_kernel32", lambda: kernel)
    monkeypatch.setattr(approvals, "_load_task_dialog", lambda: FakeComctl32(chosen))
    assert _provider()._task_dialog(_request()) == \
        approvals.ApprovalResponse(False, "cancelled")
    assert kernel.calls[-1][0] == "release"


def test_task_dialog_hresult_is_sanitized_and_context_released(monkeypatch):
    kernel = FakeKernel32()
    monkeypatch.setattr(approvals, "_load_kernel32", lambda: kernel)
    monkeypatch.setattr(
        approvals, "_load_task_dialog", lambda: FakeComctl32(0, hresult=-2147467259)
    )
    response = _provider()._task_dialog(_request())
    assert response.approved is False and response.outcome == "provider-error"
    assert response.diagnostic == "native-ui:task-dialog:hresult:0x80004005"
    assert "customer" not in response.diagnostic
    assert kernel.calls[-1][0] == "release"


def test_invalid_activation_handle_fails_closed_with_last_error(monkeypatch):
    kernel = FakeKernel32(create=approvals.INVALID_HANDLE_VALUE)
    monkeypatch.setattr(approvals, "_load_kernel32", lambda: kernel)
    monkeypatch.setattr(approvals, "_last_error", lambda: 14001)
    monkeypatch.setattr(approvals.os, "name", "nt")
    response = _provider().request(_request())
    assert response == approvals.ApprovalResponse(
        False, "provider-error", "native-ui:create-actctx:last-error:14001"
    )
    assert [call[0] for call in kernel.calls] == ["create"]


def test_activation_failure_releases_context_and_reports_error(monkeypatch):
    kernel = FakeKernel32(activate=False)
    monkeypatch.setattr(approvals, "_load_kernel32", lambda: kernel)
    monkeypatch.setattr(approvals, "_last_error", lambda: 14001)
    monkeypatch.setattr(approvals.os, "name", "nt")
    response = _provider().request(_request())
    assert response.diagnostic == "native-ui:activate-actctx:last-error:14001"
    assert [call[0] for call in kernel.calls] == ["create", "activate", "release"]


def test_deactivation_failure_still_releases_and_fails_closed(monkeypatch):
    kernel = FakeKernel32(deactivate=False)
    monkeypatch.setattr(approvals, "_load_kernel32", lambda: kernel)
    monkeypatch.setattr(approvals, "_load_task_dialog", lambda: FakeComctl32(100))
    monkeypatch.setattr(approvals, "_last_error", lambda: 6)
    monkeypatch.setattr(approvals.os, "name", "nt")
    response = _provider().request(_request())
    assert response == approvals.ApprovalResponse(
        False, "provider-error", "native-ui:deactivate-actctx:last-error:6"
    )
    assert [call[0] for call in kernel.calls][-2:] == ["deactivate", "release"]


def test_exception_diagnostic_never_contains_exception_message(monkeypatch):
    monkeypatch.setattr(approvals.os, "name", "nt")

    def fail(_request):
        raise RuntimeError("C:/private/customer.env and secret contents")

    provider = _provider()
    monkeypatch.setattr(provider, "_task_dialog", fail)
    response = provider.request(_request())
    assert response.outcome == "provider-error"
    assert response.diagnostic == "native-ui:request:exception:RuntimeError"
    assert "customer" not in response.diagnostic
