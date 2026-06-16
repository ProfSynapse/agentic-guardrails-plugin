"""Windows-shell deletion bypass surface: PowerShell / cmd wrappers.

Codex (and Cowork) on Windows route shell calls through powershell/pwsh/cmd, so
a deletion can hide inside `-Command`, `-EncodedCommand`, or `cmd /c` exactly as
it hides inside `bash -c`. These tests pin that every such form is caught, that
the regenerable-dir allowance still works through the wrappers, and that benign
PowerShell is not over-blocked.
"""
import base64
import os

from core import engine
from core.events import ALLOW, ASK, DENY, DEFER


def _enc(script: str) -> str:
    """PowerShell -EncodedCommand argument: base64 of UTF-16LE."""
    return base64.b64encode(script.encode("utf-16-le")).decode()


# ---- -Command / positional ----------------------------------------------

def test_powershell_command_remove_item_denied(evaluate):
    assert evaluate('powershell -Command "Remove-Item -Recurse -Force .codex"').action == DENY
    assert evaluate('pwsh -c "Remove-Item secret.txt"').action == DENY
    assert evaluate('powershell.exe -NoProfile -ExecutionPolicy Bypass '
                    '-Command "Remove-Item x"').action == DENY


def test_powershell_positional_command_denied(evaluate):
    # No -Command flag: first positional is the implicit command body.
    assert evaluate('powershell "Remove-Item x"').action == DENY


def test_powershell_cmd_aliases_denied(evaluate):
    for inner in ("del notes.txt", "erase notes.txt", "ri secret.txt", "rd /s /q realdir"):
        assert evaluate(f'powershell -Command "{inner}"').action == DENY, inner


# ---- cmd /c, cmd /k -------------------------------------------------------

def test_cmd_slash_c_delete_denied(evaluate):
    assert evaluate(r"cmd /c del temp\junk.log").action == DENY
    assert evaluate('cmd.exe /k "rd /s /q realdir"').action == DENY
    assert evaluate('cmd /c "del a & rd b"').action == DENY


# ---- -EncodedCommand (base64 obfuscation) ---------------------------------

def test_encoded_command_decoded_and_denied(evaluate):
    assert evaluate(f"powershell -EncodedCommand {_enc('Remove-Item -Recurse -Force x')}"
                    ).action == DENY
    assert evaluate(f"powershell -enc {_enc(chr(91) + 'System.IO.File]::Delete(0)')}"
                    ).action == DENY


def test_undecodable_encoded_command_fails_closed(evaluate):
    # Garbage that is not valid base64 must not slip through as a silent allow.
    assert evaluate("powershell -EncodedCommand @@@not-base64@@@").action in (ASK, DENY)


# ---- .NET methods and Clear-* (no clean argv0 verb) -----------------------

def test_dotnet_delete_denied(evaluate):
    assert evaluate("powershell -Command \"[System.IO.File]::Delete('x')\"").action == DENY
    assert evaluate("powershell -c \"[IO.Directory]::Delete('d', $true)\"").action == DENY


def test_clear_content_denied(evaluate):
    assert evaluate('powershell -Command "Clear-Content secrets.env"').action == DENY


# ---- pipe forms -----------------------------------------------------------

def test_pipe_into_remove_item_denied(evaluate):
    assert evaluate('powershell -Command "Get-ChildItem | Remove-Item -Force"').action == DENY
    assert evaluate('powershell -c "gci *.log | rm"').action == DENY


# ---- Invoke-Expression / iex (dynamic eval) -------------------------------

def test_iex_flagged_for_review(evaluate):
    assert evaluate('powershell -Command "iex $payload"').action == ASK


# ---- regenerable cleanup still allowed through the wrappers ---------------

def test_regenerable_cleanup_allowed_through_wrappers(evaluate):
    assert evaluate('powershell -Command "Remove-Item -Recurse -Force node_modules"').action == ALLOW
    assert evaluate('cmd /c "rd /s /q node_modules"').action == ALLOW


# ---- benign PowerShell is not over-blocked --------------------------------

def test_benign_powershell_not_blocked(evaluate):
    assert evaluate('powershell -NoProfile -Command "Get-Date"').action == DEFER
    assert evaluate('powershell -Command "Get-Content README.md"').action == DEFER


# ---- red-team round 2: forms found by adversarial review ------------------

def test_instance_delete_method_denied(evaluate):
    # (Get-Item x).Delete() and [IO.FileInfo]::new(x).Delete() don't tokenize to
    # a verb; caught by the instance-.Delete( branch of _PWSH_DESTRUCTIVE.
    assert evaluate('powershell -Command "(Get-Item secret.txt).Delete()"').action == DENY
    assert evaluate('powershell -Command "(gi secret.txt).Delete()"').action == DENY
    assert evaluate("powershell -Command \"[IO.FileInfo]::new('x').Delete()\"").action == DENY
    # raw PowerShell host (no wrapper) — Codex's exec on Windows is PowerShell.
    assert evaluate('(Get-Item secret.txt).Delete()').action == DENY


def test_move_or_rename_into_null_sink_denied(evaluate):
    assert evaluate('powershell -Command "Move-Item secret.txt -Destination NUL"').action == DENY
    assert evaluate('powershell -Command "mi secret.txt $null"').action == DENY
    # a plain rename is reversible and must not be over-blocked
    assert evaluate('powershell -Command "Rename-Item a.txt b.txt"').action == DEFER


def test_dot_source_and_scriptblock_invokers(evaluate):
    assert evaluate('powershell -Command ". Remove-Item secret.txt"').action == DENY
    assert evaluate('powershell -Command "icm {Remove-Item secret.txt}"').action == ASK
    assert evaluate('powershell -Command "Invoke-Command {Remove-Item secret.txt}"').action == ASK


def test_cmd_switch_filter_does_not_allow_posix_root_path(evaluate):
    # Regression: the /s-style switch filter must not drop a real POSIX path
    # like /e from rm's operands and silently allow deleting it.
    assert evaluate("rm -rf node_modules /e").action == DENY
    assert evaluate("rm node_modules /e").action == DENY


# ---- red-team round 3: ForEach/scriptblock-hidden deletes -----------------

def test_foreach_instance_delete_denied(evaluate):
    # The canonical PowerShell "delete all matching files" idiom.
    assert evaluate('powershell -Command "gi x | %{$_.Delete()}"').action == DENY
    assert evaluate('powershell -Command "Get-ChildItem *.txt | '
                    'ForEach-Object { $_.Delete() }"').action == DENY
    assert evaluate('powershell -Command "gci -r | % Delete"').action == DENY


def test_moveto_null_sink_denied(evaluate):
    assert evaluate("powershell -Command \"(Get-Item x).MoveTo('NUL')\"").action == DENY
    # a real move destination is reversible and must not be over-blocked
    assert evaluate("powershell -Command \"(Get-Item x).MoveTo('backup/x')\"").action == DEFER


def test_scriptblock_and_call_operator_delete_denied(evaluate):
    assert evaluate('powershell -Command "& { Remove-Item secret.txt }"').action == DENY
    assert evaluate('powershell -Command "&{Remove-Item secret.txt}"').action == DENY
    assert evaluate('powershell -Command ". { Remove-Item x }"').action == DENY
    assert evaluate('powershell -Command "1..3 | % { Remove-Item x$_ }"').action == DENY


def test_pipeline_property_read_not_over_asked(evaluate):
    # $_ / $PSItem property access is not command indirection; benign reads in a
    # ForEach block should pass, not prompt.
    assert evaluate('powershell -Command "Get-ChildItem | % { $_.Name }"').action == DEFER
    assert evaluate('powershell -Command "1..3 | % { Write-Host $_ }"').action == DEFER


# ---- Cat 4: destructive overwrites are pre-imaged (recoverable) ------------

def test_powershell_overwrites_are_snapshot_targets(tmp_path):
    target = tmp_path / "important.txt"
    src = tmp_path / "junk"
    target.write_text("ORIGINAL")
    src.write_text("x")
    d = str(tmp_path)

    def clobbers(cmd):
        return os.path.basename(str(target)) in [
            os.path.basename(p) for p in engine.clobber_targets(cmd, d)]

    # in-place overwrites that carry no `>` token must still be captured
    assert clobbers('powershell -Command "Set-Content important.txt \'\'"')
    assert clobbers('powershell -Command "Set-Content -Path important.txt -Value \'\'"')
    assert clobbers('powershell -Command "Out-File -FilePath important.txt"')
    assert clobbers('cmd /c "copy /y junk important.txt"')
    assert clobbers('powershell -Command "Copy-Item junk important.txt -Force"')
    assert clobbers("powershell -Command \"[IO.File]::WriteAllText('important.txt','')\"")


def test_append_forms_are_not_snapshot_targets(tmp_path):
    target = tmp_path / "log.txt"
    target.write_text("ORIGINAL")
    d = str(tmp_path)

    def clobbers(cmd):
        return any(os.path.basename(p) == "log.txt" for p in engine.clobber_targets(cmd, d))

    # appends do not lose the original, so they should not be pre-imaged
    assert not clobbers('powershell -Command "Out-File -FilePath log.txt -Append"')
    assert not clobbers('powershell -Command "Add-Content log.txt \'x\'"')
