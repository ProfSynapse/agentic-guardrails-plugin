"""Terminal confirmation UX and reviewer-generated challenge tests."""
import io
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugin/scripts"))
from core import linux_review as review


@pytest.mark.parametrize("typed,expected,message", [
    ("approve aaaaaaaaaaaa\n", True, "Approval phrase accepted."),
    ("approve " + "b" * 32 + "\n", False, "DECLINED"),
    ("\n", False, "DECLINED"),
])
def test_terminal_challenge_generated_by_reviewer(monkeypatch, capsys, typed, expected, message):
    source = io.StringIO(typed)
    monkeypatch.setattr(source, "isatty", lambda: True)
    monkeypatch.setattr(sys, "stdin", source)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(review.uuid, "uuid4", lambda: SimpleNamespace(hex="a" * 32))
    monkeypatch.setattr(review.select, "select", lambda *args: ([source], [], []))
    assert review.terminal_review({"input": {"body": "fixture"}}, "b" * 32,
                                  time.time() + 30) is expected
    output = capsys.readouterr().out
    assert "\napprove aaaaaaaaaaaa\n" in output
    assert "b" * 32 not in output
    assert message in output


def test_terminal_expiry_is_visible_and_never_reads_old_input(monkeypatch, capsys):
    source = io.StringIO("approve stale\n")
    monkeypatch.setattr(source, "isatty", lambda: True)
    monkeypatch.setattr(sys, "stdin", source)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(review.select, "select", lambda *args: ([], [], []))
    assert not review.terminal_review({}, "b" * 32, time.time() + 30)
    assert "EXPIRED" in capsys.readouterr().out
    assert source.tell() == 0
