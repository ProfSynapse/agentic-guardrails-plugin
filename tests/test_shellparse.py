"""Shell parser unit tests."""
import pytest

from core.shellparse import (FLAG_DECODE_PIPE, FLAG_INDIRECT, ParseUncertain,
                             extract_commands, extract_payloads)


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
