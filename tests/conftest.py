import os
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts"))
sys.path.insert(0, os.path.join(REPO, "scripts", "agw"))


@pytest.fixture(autouse=True)
def agw_home(tmp_path, monkeypatch):
    """Every test gets an isolated archive store on a real (ext4) filesystem."""
    home = tmp_path / "agw-home"
    monkeypatch.setenv("AGW_HOME", str(home))
    yield str(home)


@pytest.fixture()
def policy():
    from core import engine
    return engine.load_policy(REPO)


@pytest.fixture()
def evaluate(policy):
    from core import engine
    from core.events import ToolEvent, EXEC

    def _run(command: str):
        return engine.evaluate(
            ToolEvent(kind=EXEC, tool="Bash", command=command, cwd=os.getcwd()),
            policy, REPO)
    return _run
