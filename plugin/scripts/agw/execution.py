"""Bounded process execution independent from output/recovery policy.

Filesystem isolation is represented as a capability instead of being implied
by after-the-fact observation.  Unsupported isolation requests fail closed.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import signal
import subprocess
import tempfile
import time
from typing import Protocol


MAX_CAPTURE_BYTES = 64 * 1024
DEFAULT_TIMEOUT_SECONDS = 300.0
MAX_TIMEOUT_SECONDS = 24 * 60 * 60.0


class ExecutionError(RuntimeError):
    error_code = "execution_error"

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.details = details or {}


class IsolationUnavailable(ExecutionError):
    error_code = "isolation_unavailable"


@dataclass(frozen=True)
class IsolationRequest:
    mode: str = "observed"  # observed | read-only | strict
    network: str = "inherit"  # inherit | deny


@dataclass(frozen=True)
class ExecutionRequest:
    command: list[str]
    cwd: str
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    isolation: IsolationRequest = IsolationRequest()


@dataclass(frozen=True)
class ExecutionResult:
    exit_code: int
    stdout_tail: str
    stderr_tail: str
    capture_truncated: bool
    timed_out: bool
    duration_seconds: float
    isolation_mode: str
    network_policy: str


class IsolationProvider(Protocol):
    def run(self, request: ExecutionRequest) -> ExecutionResult:
        ...


def _validate_request(request: ExecutionRequest) -> None:
    if not request.command:
        raise ExecutionError("execution requires a command")
    if not os.path.isdir(request.cwd):
        raise ExecutionError("execution working directory does not exist")
    try:
        timeout = float(request.timeout_seconds)
    except (TypeError, ValueError) as exc:
        raise ExecutionError("timeout must be a finite number") from exc
    if not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise ExecutionError(
            f"timeout must be greater than zero and at most {MAX_TIMEOUT_SECONDS:g} seconds"
        )
    if request.isolation.mode not in {"observed", "read-only", "strict"}:
        raise ExecutionError("unknown execution isolation mode")
    if request.isolation.network not in {"inherit", "deny"}:
        raise ExecutionError("network policy must be inherit or deny")


def _captured(handle) -> tuple[str, bool]:
    handle.flush()
    size = handle.tell()
    handle.seek(max(0, size - MAX_CAPTURE_BYTES))
    payload = handle.read()
    return payload.decode("utf-8", "replace"), size > MAX_CAPTURE_BYTES


def _terminate_tree(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=10, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            process.kill()
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        process.kill()


class ObservedProcessRunner:
    """Bounded execution without claiming filesystem or network isolation."""

    def run(self, request: ExecutionRequest) -> ExecutionResult:
        _validate_request(request)
        if request.isolation.mode != "observed" or request.isolation.network != "inherit":
            raise IsolationUnavailable(
                "the installed runtime has no OS isolation provider for this request",
                {"requested_mode": request.isolation.mode,
                 "network_policy": request.isolation.network,
                 "fallback_performed": False},
            )
        started = time.monotonic()
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) \
            if os.name == "nt" else 0
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            try:
                process = subprocess.Popen(
                    request.command, cwd=request.cwd, stdin=subprocess.DEVNULL,
                    stdout=stdout_file, stderr=stderr_file,
                    start_new_session=os.name != "nt", creationflags=creationflags,
                )
            except OSError as exc:
                raise ExecutionError(f"command could not be started: {exc}") from exc
            timed_out = False
            try:
                process.wait(timeout=float(request.timeout_seconds))
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_tree(process)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            stdout, stdout_truncated = _captured(stdout_file)
            stderr, stderr_truncated = _captured(stderr_file)
        return ExecutionResult(
            exit_code=int(process.returncode if process.returncode is not None else -1),
            stdout_tail=stdout,
            stderr_tail=stderr,
            capture_truncated=stdout_truncated or stderr_truncated,
            timed_out=timed_out,
            duration_seconds=max(0.0, time.monotonic() - started),
            isolation_mode="observed",
            network_policy="inherit",
        )


DEFAULT_RUNNER: IsolationProvider = ObservedProcessRunner()


def run(request: ExecutionRequest, *, provider: IsolationProvider | None = None) -> ExecutionResult:
    return (provider or DEFAULT_RUNNER).run(request)
