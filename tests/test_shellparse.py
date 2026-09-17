"""Shell parser unit tests."""
import pytest

from core.shellparse import (DIALECT_POSIX, DIALECT_POWERSHELL, FLAG_DECODE_PIPE,
                             FLAG_INDIRECT, FLAG_INNER_UNCERTAIN,
                             FLAG_UNINSPECTED_SCRIPT, ParseUncertain,
                             _detect_dialect, extract_commands, extract_payloads)


def names(command):
    return [c.name for c in extract_commands(command).commands]


def test_operator_splitting():
    assert names("git add . && git commit -m 'x'; ls | wc -l") == \
        ["git", "git", "ls", "wc"]


def test_substitution_recursion():
    parsed = extract_commands("echo $(rm -rf /tmp/x)")
    assert "rm" in [c.name for c in parsed.commands]


def test_backtick_recursion():
    assert "rm" in names("`rm file`")


def test_bash_c_recursion():
    assert "rm" in names("bash -c 'rm -rf /tmp/y'")


def test_nested_bash_c():
    assert "rm" in names("bash -c \"bash -c 'rm x'\"")


def test_xargs_extraction():
    assert "rm" in names("ls | xargs rm -f")


def test_xargs_with_flags():
    assert "rm" in names("cat f | xargs -n1 -I{} rm {}")


def test_find_exec_extraction():
    assert "rm" in names("find . -name '*.tmp' -exec rm {} \\;")


def test_wrapper_stripping():
    parsed = extract_commands("timeout 30 rm -rf x")
    assert any(c.name == "rm" for c in parsed.commands)


def test_path_normalization():
    assert names("/usr/bin/RM -rf /")[0] == "rm"


def test_indirection_flagged():
    parsed = extract_commands("$CMD file.txt")
    assert FLAG_INDIRECT in parsed.flags


def test_decode_pipe_flagged():
    parsed = extract_commands("echo cm0= | base64 -d | sh")
    assert FLAG_DECODE_PIPE in parsed.flags


def test_unterminated_quote_raises():
    with pytest.raises(ParseUncertain):
        extract_commands("rm 'unterminated")


def test_depth_limit_raises():
    cmd = "echo hi"
    for _ in range(10):
        cmd = f"echo $({cmd})"
    with pytest.raises(ParseUncertain):
        extract_commands(cmd)


def test_quoted_filenames_with_spaces():
    parsed = extract_commands("cat 'my file with spaces.txt'")
    assert parsed.commands[0].argv == ["cat", "my file with spaces.txt"]


def test_heredoc_payload_extraction():
    payloads = extract_payloads("cat > f.txt <<EOF\nsecret content here\nEOF")
    assert any("secret content" in p for p in payloads)


def test_var_assignment_prefix():
    assert names("FOO=bar ls -la") == ["ls"]


def test_powershell_subexpression_not_posix_unbalanced():
    parsed = extract_commands("Write-Host $(Get-Date)")
    assert {c.name for c in parsed.commands} >= {"write-host", "get-date"}
    assert FLAG_INDIRECT not in parsed.flags


def test_powershell_literal_variable_invocation_resolves():
    parsed = extract_commands("$cmd = 'Get-Date'; & $cmd")
    assert "get-date" in [c.name for c in parsed.commands]
    assert FLAG_INDIRECT not in parsed.flags


def test_powershell_env_assignment_prefix_is_data():
    parsed = extract_commands(
        "$env:AGW_TEST_MODE='1'; $env:AGW_APPROVAL_PROVIDER='headless'; python -m pytest")
    assert [c.name for c in parsed.commands] == ["python"]
    assert FLAG_INDIRECT not in parsed.flags


def test_powershell_null_redirection_is_not_command_indirection():
    parsed = extract_commands(
        "rg -n 'version' plugin README.md 2>$null",
        dialect=DIALECT_POWERSHELL,
    )
    assert [command.name for command in parsed.commands] == ["rg"]
    assert FLAG_INDIRECT not in parsed.flags


def test_windows_backslash_path_preserved():
    # shlex(posix) would eat the backslash and collapse `secrets\.env` to
    # `secrets.env`; the normalizer keeps it so path detection still works.
    parsed = extract_commands(r"Get-Content secrets\.env")
    assert parsed.commands[0].argv == ["Get-Content", r"secrets\.env"]
    parsed = extract_commands(r"type confidential\board-notes.txt")
    assert parsed.commands[0].argv[1] == r"confidential\board-notes.txt"


def test_posix_backslash_escapes_still_work():
    # A backslash before a shell metacharacter is a POSIX escape, not a Windows
    # separator, and must keep its meaning.
    assert extract_commands(r"cat my\ file.txt").commands[0].argv == ["cat", "my file.txt"]
    assert "rm" in names("find . -name '*.tmp' -exec rm {} \\;")


def test_exe_suffix_stripped_from_name():
    assert names("curl.exe https://x") == ["curl"]
    assert names(r"C:\tools\wget.exe url") == ["wget"]


def test_powershell_wrapper_and_encoded_payload_preserve_dialect():
    direct = extract_commands('powershell -Command "Set-Content victim.txt changed"')
    inner = next(cmd for cmd in direct.commands if cmd.name == "set-content")
    assert inner.dialect == DIALECT_POWERSHELL


@pytest.mark.parametrize("escaped,canonical", [
    ("victim`.txt", "victim.txt"),
    ("victim`-old.txt", "victim-old.txt"),
    ("victim`_old.txt", "victim_old.txt"),
    ("dir`/victim.txt", "dir/victim.txt"),
    (r"dir`\victim.txt", r"dir\victim.txt"),
])
def test_powershell_static_backtick_escape_table(escaped, canonical):
    parsed = extract_commands(
        f"Set-Content {escaped} changed", dialect=DIALECT_POWERSHELL
    )
    assert parsed.commands[0].argv == ["Set-Content", canonical, "changed"]


@pytest.mark.parametrize("script", [
    "Set-Content victim`$name changed",
    'Set-Content victim`"name changed',
    "Set-Content victim`n.txt changed",
    "Set-Content victim` changed",
])
def test_powershell_ambiguous_backtick_escapes_are_uncertain(script):
    with pytest.raises(ParseUncertain):
        extract_commands(script, dialect=DIALECT_POWERSHELL)


def test_encoded_powershell_inner_failure_preserves_payload_provenance():
    import base64
    script = "Set-Content victim`n.txt changed"
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    parsed = extract_commands(f"pwsh -EncodedCommand {encoded}")
    assert FLAG_INNER_UNCERTAIN in parsed.flags
    assert script in parsed.payloads

    import base64
    encoded = base64.b64encode(
        "Set-Content victim.txt changed".encode("utf-16-le")
    ).decode()
    parsed = extract_commands(f"pwsh -EncodedCommand {encoded}")
    inner = next(cmd for cmd in parsed.commands if cmd.name == "set-content")
    assert inner.dialect == DIALECT_POWERSHELL


# ---- F3: one normalized interpreter head before every wrapper test --------

@pytest.mark.parametrize("command, inner", [
    ('bash.exe -c "rm -rf X"', "rm"),
    ('BASH.EXE -c "rm -rf X"', "rm"),
    ('sh.exe -c "rm file"', "rm"),
    ('"C:\\Program Files\\PortableShell\\bin\\bash.exe" -c "rm -rf X"', "rm"),
    (r"C:\Windows\System32\cmd.exe /c del X", "del"),
    (r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
     r' -Command "Remove-Item -Recurse -Force C:\x"', "remove-item"),
    ('"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -c '
     '"Remove-Item -Recurse -Force C:\\x"', "remove-item"),
    (r"cmd.bat /c del X", "del"),
])
def test_suffixed_and_full_path_interpreters_are_recursed(command, inner):
    assert inner in names(command)


def test_normalized_head_does_not_rename_the_wrapper_itself():
    # Only the wrapper *lookup* is normalized; SimpleCommand.name keeps the
    # spelling downstream tables (and the launcher handshake) rely on.
    parsed = extract_commands("agw.cmd status")
    assert [c.name for c in parsed.commands] == ["agw.cmd"]


# ---- F4: wsl, Start-Process, and the uninspected -File script ------------

@pytest.mark.parametrize("command", [
    "wsl rm -rf /mnt/c/Users/jo/Documents",
    "wsl.exe rm -rf /mnt/c/x",
    "wsl -d Ubuntu -u root rm -rf /mnt/c/x",
    "wsl -e rm -rf /mnt/c/x",
    "wsl --exec rm -rf /mnt/c/x",
    "wsl -- rm -rf /mnt/c/x",
    "wsl --cd /tmp rm -rf /mnt/c/x",
    'wsl bash -c "rm -rf /mnt/c/x"',
])
def test_wsl_inner_command_is_recursed(command):
    assert "rm" in names(command), command


def test_wsl_without_an_inner_command_stays_one_command():
    assert names("wsl --list --verbose") == ["wsl"]


@pytest.mark.parametrize("command", [
    "Start-Process powershell -ArgumentList '-Command','Remove-Item -Recurse C:\\x'",
    "saps pwsh -ArgumentList '-c','Remove-Item y.txt'",
    'Start-Process -FilePath cmd.exe -ArgumentList "/c del X"',
    'start powershell -ArgumentList "-Command Remove-Item y.txt"',
])
def test_start_process_argument_list_is_recursed(command):
    parsed = extract_commands(command, dialect=DIALECT_POWERSHELL)
    assert {"remove-item", "del"} & {c.name for c in parsed.commands}, command


def test_start_process_of_a_non_interpreter_is_not_unwrapped():
    parsed = extract_commands("Start-Process notepad.exe README.md",
                              dialect=DIALECT_POWERSHELL)
    assert [c.name for c in parsed.commands] == ["start-process"]
    assert not parsed.flags


@pytest.mark.parametrize("command", [
    "Start-Process powershell -ArgumentList $cmd",
    "Start-Process powershell -ArgumentList @args",
    "Start-Process powershell -ArgumentList (Get-Content list.txt)",
    "Start-Process -FilePath pwsh -ArgumentList",
])
def test_start_process_with_a_dynamic_argument_list_fails_closed(command):
    parsed = extract_commands(command, dialect=DIALECT_POWERSHELL)
    assert FLAG_INDIRECT in parsed.flags, command
    assert FLAG_UNINSPECTED_SCRIPT in parsed.flags, command


def test_powershell_file_records_the_uninspected_script():
    parsed = extract_commands(r"powershell -NoProfile -File C:\tools\wipe.ps1")
    assert FLAG_UNINSPECTED_SCRIPT in parsed.flags
    assert parsed.uninspected == [r"C:\tools\wipe.ps1"]


def test_uninspected_script_survives_wrapper_recursion():
    parsed = extract_commands('cmd /c "powershell -File wipe.ps1"')
    assert FLAG_UNINSPECTED_SCRIPT in parsed.flags
    assert parsed.uninspected == ["wipe.ps1"]


# ---- F7: $var heads and a cmdlet-shaped dialect detector -----------------

@pytest.mark.parametrize("command", [
    "$deleter -Recurse C:\\work",
    "$cmd notes.txt",
    "& $tool -Force x",
])
def test_powershell_variable_head_is_flagged_indirect(command):
    parsed = extract_commands(command, dialect=DIALECT_POWERSHELL)
    assert parsed.commands, command
    assert FLAG_INDIRECT in parsed.flags, command


def test_powershell_pipeline_current_object_is_not_indirection():
    parsed = extract_commands("Get-ChildItem | % { $_.Name }",
                              dialect=DIALECT_POWERSHELL)
    assert FLAG_INDIRECT not in parsed.flags


@pytest.mark.parametrize("command", [
    'curl -H "Content-Type: application/json" https://x.test',
    'curl -H "X-Request-Id: abc" https://x.test',
    "echo Foo-Bar",
    "grep My-App src/",
    "make Build-All",
])
def test_hyphenated_words_are_not_powershell(command):
    assert _detect_dialect(command) == DIALECT_POSIX, command


@pytest.mark.parametrize("command", [
    "Get-ChildItem .",
    "Remove-Item -Recurse x",
    "Start-Process notepad",
    "ConvertTo-Json $x",
    "$env:PATH = 'x'",
    "echo $PSItem",
])
def test_real_cmdlet_shapes_are_powershell(command):
    assert _detect_dialect(command) == DIALECT_POWERSHELL, command


def test_variable_head_on_the_bash_tool_is_no_longer_dialect_confused():
    # `My-Documents` used to match the loose cmdlet regex, switch the line into
    # the PowerShell dialect, and vanish through the `$var` early return.
    parsed = extract_commands("$RM -rf ~/My-Documents")
    assert [c.argv for c in parsed.commands] == [["$RM", "-rf", "~/My-Documents"]]
    assert FLAG_INDIRECT in parsed.flags


# ---- G5: backtick line continuation ------------------------------------

def test_powershell_line_continuation_is_collapsed_not_uncertain():
    parsed = extract_commands("Copy-Item README.md README.bak `\n  -Force",
                              dialect=DIALECT_POWERSHELL)
    assert [c.argv for c in parsed.commands] == \
        [["Copy-Item", "README.md", "README.bak", "-Force"]]


def test_powershell_multi_line_deletion_is_parsed():
    parsed = extract_commands(
        "Remove-Item `\n  -Recurse `\n  -Force C:\\work\\notes",
        dialect=DIALECT_POWERSHELL)
    assert [c.name for c in parsed.commands] == ["remove-item"]


def test_powershell_line_continuation_joins_the_token():
    # PowerShell consumes the backtick and the newline entirely, so the
    # characters on either side end up in one token.
    parsed = extract_commands("Set-Content victim`\n.txt changed",
                              dialect=DIALECT_POWERSHELL)
    assert parsed.commands[0].argv == ["Set-Content", "victim.txt", "changed"]


def test_powershell_crlf_line_continuation_is_collapsed():
    parsed = extract_commands("Copy-Item a.txt b.txt `\r\n  -Force",
                              dialect=DIALECT_POWERSHELL)
    assert [c.argv for c in parsed.commands] == \
        [["Copy-Item", "a.txt", "b.txt", "-Force"]]


@pytest.mark.parametrize("script", [
    # A backtick-space is an escaped space; the statement really does end at
    # the newline, so joining the lines would parse a command that never runs.
    "Write-Output a` \nRemove-Item -Recurse -Force C:\\work",
    "Write-Output a`b",
    "Write-Output a`",
    "Set-Content victim`'name changed",
])
def test_unpaired_backticks_elsewhere_stay_uncertain(script):
    with pytest.raises(ParseUncertain):
        extract_commands(script, dialect=DIALECT_POWERSHELL)
