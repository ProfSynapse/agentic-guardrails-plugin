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

from core.outcomes import (
    ContractOutcome, ProcessOutcome, PublicationOutcome, completed_record,
    composite_outcome,
)


MAX_CAPTURE_BYTES = 64 * 1024
DEFAULT_TIMEOUT_SECONDS = 300.0
MAX_TIMEOUT_SECONDS = 24 * 60 * 60.0
SCRIPT_EXECUTION_INTEGRITY_VALUES = frozenset({"none", "verified-immutable"})


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
class ProviderCapabilities:
    """Claims a provider can truthfully make before execution."""
    isolation_modes: tuple[str, ...]
    network_policies: tuple[str, ...]
    filesystem_enforcement: bool = False
    network_enforcement: bool = False
    bounded_tail_capture: bool = False
    provider_identity: str = ""
    script_execution_integrity: str = "none"

    def __post_init__(self) -> None:
        if self.script_execution_integrity not in SCRIPT_EXECUTION_INTEGRITY_VALUES:
            raise ValueError("unknown script execution integrity attestation")


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
    process_outcome: str = ""
    execution_started: bool = True
    fallback_performed: bool = False
    publication_outcome: str = PublicationOutcome.NOT_APPLICABLE.value
    provider_identity: str = ""
    script_execution_integrity: str = "none"
    filesystem_enforcement: bool = False
    network_enforcement: bool = False

    def __post_init__(self) -> None:
        if not self.process_outcome:
            value = (ProcessOutcome.TIMED_OUT.value if self.timed_out else
                     ProcessOutcome.SUCCEEDED.value if self.exit_code == 0 else
                     ProcessOutcome.FAILED.value)
            object.__setattr__(self, "process_outcome", value)
        else:
            ProcessOutcome(self.process_outcome)
        PublicationOutcome(self.publication_outcome)
        if self.script_execution_integrity not in SCRIPT_EXECUTION_INTEGRITY_VALUES:
            raise ValueError("unknown script execution integrity attestation")
        process = ProcessOutcome(self.process_outcome)
        if process is ProcessOutcome.SUCCEEDED and (
                not self.execution_started or self.timed_out
                or self.fallback_performed or self.exit_code != 0):
            raise ValueError(
                "a successful process requires started execution, exit zero, "
                "no timeout, and no fallback"
            )
        if process is ProcessOutcome.NOT_STARTED and (
                self.execution_started or self.timed_out or self.exit_code == 0):
            raise ValueError(
                "a not-started process requires execution_started=false and "
                "cannot report timeout or a successful exit"
            )
        if process is ProcessOutcome.TIMED_OUT and (
                not self.execution_started or not self.timed_out
                or self.exit_code == 0):
            raise ValueError(
                "a timed-out process requires started execution, timed_out=true, "
                "and a nonzero exit"
            )
        if process is ProcessOutcome.FAILED and (
                not self.execution_started or self.timed_out or self.exit_code == 0):
            raise ValueError(
                "a failed process requires started execution, no timeout, and "
                "a nonzero exit"
            )
        if self.fallback_performed and (
                self.filesystem_enforcement or self.network_enforcement):
            raise ValueError(
                "fallback execution cannot attest requested enforcement"
            )

    @property
    def ok(self) -> bool:
        return self.process_outcome == ProcessOutcome.SUCCEEDED.value

    @property
    def exit(self) -> int:
        return self.exit_code

    @property
    def operation_outcome(self) -> str:
        return composite_outcome(
            process_outcome=self.process_outcome,
            contract_outcome=ContractOutcome.SATISFIED,
        ).value

    @property
    def outcome(self) -> str:
        return self.operation_outcome

    def to_dict(self) -> dict:
        result = {
            "exit_code": self.exit_code, "exit": self.exit_code, "ok": self.ok,
            "stdout_tail": self.stdout_tail, "stderr_tail": self.stderr_tail,
            "capture_truncated": self.capture_truncated,
            "timed_out": self.timed_out, "duration_seconds": self.duration_seconds,
            "isolation_mode": self.isolation_mode,
            "network_policy": self.network_policy,
            "process_outcome": self.process_outcome,
            "execution_started": self.execution_started,
            "fallback_performed": self.fallback_performed,
            "contract_outcome": ContractOutcome.SATISFIED.value,
            "publication_outcome": self.publication_outcome,
            "provider_identity": self.provider_identity,
            "script_execution_integrity": self.script_execution_integrity,
            "filesystem_enforcement": self.filesystem_enforcement,
            "network_enforcement": self.network_enforcement,
        }
        return completed_record(result)


class IsolationProvider(Protocol):
    capabilities: ProviderCapabilities

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

    capabilities = ProviderCapabilities(
        isolation_modes=("observed",), network_policies=("inherit",),
        bounded_tail_capture=True,
        provider_identity="observed-process-runner",
        script_execution_integrity="none",
        filesystem_enforcement=False, network_enforcement=False,
    )

    def run(self, request: ExecutionRequest) -> ExecutionResult:
        _validate_request(request)
        if request.isolation.mode != "observed" or request.isolation.network != "inherit":
            raise IsolationUnavailable(
                "the installed runtime has no OS isolation provider for this request",
                {"requested_mode": request.isolation.mode,
                 "network_policy": request.isolation.network,
                 "execution_started": False,
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
                raise ExecutionError(
                    f"command could not be started: {exc}",
                    {"execution_started": False, "fallback_performed": False},
                ) from exc
            try:
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
                else:
                    timed_out = False
                stdout, stdout_truncated = _captured(stdout_file)
                stderr, stderr_truncated = _captured(stderr_file)
            except (OSError, subprocess.SubprocessError) as exc:
                _terminate_tree(process)
                raise ExecutionError(
                    f"execution failed after the command started: {exc}",
                    {"execution_started": True, "fallback_performed": False},
                ) from exc
        return ExecutionResult(
            exit_code=int(process.returncode if process.returncode is not None else -1),
            stdout_tail=stdout,
            stderr_tail=stderr,
            capture_truncated=stdout_truncated or stderr_truncated,
            timed_out=timed_out,
            duration_seconds=max(0.0, time.monotonic() - started),
            isolation_mode="observed",
            network_policy="inherit",
            execution_started=True,
            fallback_performed=False,
            provider_identity=self.capabilities.provider_identity,
            script_execution_integrity=
                self.capabilities.script_execution_integrity,
            filesystem_enforcement=self.capabilities.filesystem_enforcement,
            network_enforcement=self.capabilities.network_enforcement,
        )


DEFAULT_RUNNER: IsolationProvider = ObservedProcessRunner()


def run(request: ExecutionRequest, *, provider: IsolationProvider | None = None) -> ExecutionResult:
    try:
        return (provider or DEFAULT_RUNNER).run(request)
    except ExecutionError as exc:
        exc.details.setdefault("execution_started", False)
        exc.details.setdefault("fallback_performed", False)
        raise
