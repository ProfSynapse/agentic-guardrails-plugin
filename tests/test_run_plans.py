import copy
import os
import sys
import time

import pytest

import execution
import run_plans
from core import recovery_contracts, store


def _writer(tmp_path, body=None):
    script = tmp_path / "writer.py"
    script.write_text(body or (
        "from pathlib import Path\n"
        "import sys\n"
        "Path(sys.argv[1]).write_text('built', encoding='utf-8')\n"
    ), encoding="utf-8")
    return script


def _staged_plan(tmp_path, **overrides):
    script = _writer(tmp_path)
    stage = tmp_path / "stage.bin"
    target = tmp_path / "target.bin"
    target.write_text("old", encoding="utf-8")
    arguments = {
        "mode": "staged-publish", "cwd": str(tmp_path),
        "artifacts": [{"staged": str(stage), "target": str(target)}],
    }
    arguments.update(overrides)
    plan = run_plans.create_run_plan(
        [sys.executable, str(script), str(stage)], **arguments,
    )
    return plan, stage, target, script


def test_create_is_canonical_strict_and_normalizes_script(tmp_path):
    plan, stage, target, script = _staged_plan(tmp_path)
    assert plan["schema"] == "agw-run-plan/v1"
    assert recovery_contracts.plan_hash_valid(plan)
    assert len(plan["freshness"]["plan_id"]) == 32
    assert plan["freshness"]["max_uses"] == 1
    assert plan["command"] == {
        "runtime": "python", "script": os.path.realpath(script),
        "script_sha256": store.file_sha256(str(script)), "args": [str(stage)],
    }
    assert plan["artifacts"][0]["target_before"] == store.file_sha256(str(target))
    tampered = copy.deepcopy(plan)
    tampered["extra"] = True
    tampered = recovery_contracts.bind_plan_hash(tampered)
    with pytest.raises(run_plans.RunPlanError, match="fields"):
        run_plans.validate_run_plan(tampered)


def test_tamper_stale_and_future_plans_are_rejected(tmp_path):
    plan, *_ = _staged_plan(tmp_path)
    tampered = copy.deepcopy(plan)
    tampered["command"]["args"].append("other")
    with pytest.raises(run_plans.RunPlanError, match="self-hash"):
        run_plans.validate_run_plan(tampered)
    stale, *_ = _staged_plan(
        tmp_path, issued_at_utc=time.time() - 1000, expires_at_utc=time.time() - 1,
    )
    with pytest.raises(run_plans.RunPlanExpired):
        run_plans.validate_run_plan(stale)
    future, *_ = _staged_plan(
        tmp_path, issued_at_utc=time.time() + 301, expires_at_utc=time.time() + 600,
    )
    with pytest.raises(run_plans.RunPlanExpired):
        run_plans.validate_run_plan(future)


def test_duplicate_artifact_paths_are_rejected(tmp_path):
    script = _writer(tmp_path)
    same = tmp_path / "same.bin"
    with pytest.raises(run_plans.RunPlanError, match="same filesystem identity"):
        run_plans.create_run_plan(
            [sys.executable, str(script), str(same)], mode="staged-publish",
            cwd=str(tmp_path), artifacts=[{"staged": str(same), "target": str(same)}],
        )


def test_dry_run_checks_preconditions_without_claiming(tmp_path):
    plan, *_ = _staged_plan(tmp_path)
    first = run_plans.apply_run_plan(plan, expected_plan_hash=plan["plan_sha256"], dry_run=True)
    second = run_plans.apply_run_plan(plan, expected_plan_hash=plan["plan_sha256"], dry_run=True)
    assert first["dry_run"] and second["dry_run"]
    assert first["process_outcome"] == "not_applicable"
    assert first["publication_outcome"] == "validated"
    assert first["operation_outcome"] == first["outcome"] == "success"
    assert first["claimed"] is first["consumed"] is False
    assert not (tmp_path / "agw-home" / run_plans.CONSUMPTION_LOG).exists()


def test_preclaim_conflict_does_not_consume(tmp_path):
    plan, _stage, target, _script = _staged_plan(tmp_path)
    target.write_text("changed", encoding="utf-8")
    with pytest.raises(run_plans.RunPlanConflict):
        run_plans.apply_run_plan(plan)
    assert not (tmp_path / "agw-home" / run_plans.CONSUMPTION_LOG).exists()


def test_installed_provider_fails_stdout_read_only_before_claim(tmp_path):
    script = _writer(tmp_path, "print('safe')\n")
    plan = run_plans.create_run_plan(
        [sys.executable, str(script)], mode="stdout-read-only", cwd=str(tmp_path),
        isolation="read-only",
    )
    result = run_plans.apply_run_plan(plan)
    assert result["outcome"] == "environment_failure"
    assert result["error_code"] == "immutable_execution_unavailable"
    assert result["execution_started"] is False
    assert result["fallback_performed"] is False
    assert result["process_outcome"] == "not_started"
    assert result["contract_outcome"] == "not_evaluated"
    assert result["publication_outcome"] == "not_attempted"
    assert result["recovery_state"] == "NOT_STARTED"
    assert result["claimed"] is result["consumed"] is False
    assert not (tmp_path / "agw-home" / run_plans.CONSUMPTION_LOG).exists()


def test_stdout_dry_run_is_nonprocess_and_does_not_require_provider(tmp_path):
    script = _writer(tmp_path, "print('safe')\n")
    plan = run_plans.create_run_plan(
        [sys.executable, str(script)], mode="stdout-read-only", cwd=str(tmp_path),
        isolation="read-only",
    )
    result = run_plans.apply_run_plan(plan, dry_run=True)
    assert result["process_outcome"] == "not_applicable"
    assert result["publication_outcome"] == "not_attempted"
    assert result["operation_outcome"] == result["outcome"] == "success"
    assert result["execution_started"] is False
    assert result["claimed"] is result["consumed"] is False


def test_installed_provider_also_refuses_staged_execution_before_claim(tmp_path):
    plan, *_ = _staged_plan(tmp_path)
    result = run_plans.apply_run_plan(plan)
    assert result["operation_outcome"] == "environment_failure"
    assert result["error_code"] == "immutable_execution_unavailable"
    assert result["claimed"] is result["consumed"] is False


class VerifiedObservedProvider:
    capabilities = execution.ProviderCapabilities(
        isolation_modes=("observed",), network_policies=("inherit",),
        filesystem_enforcement=False, network_enforcement=False,
        bounded_tail_capture=True, script_execution_integrity="verified-immutable",
        provider_identity="installed",
    )

    def run(self, request):
        result = execution.DEFAULT_RUNNER.run(request)
        return execution.ExecutionResult(
            exit_code=result.exit_code, stdout_tail=result.stdout_tail,
            stderr_tail=result.stderr_tail,
            capture_truncated=result.capture_truncated,
            timed_out=result.timed_out, duration_seconds=result.duration_seconds,
            isolation_mode=result.isolation_mode,
            network_policy=result.network_policy,
            process_outcome=result.process_outcome,
            execution_started=result.execution_started,
            fallback_performed=result.fallback_performed,
            provider_identity=self.capabilities.provider_identity,
            script_execution_integrity=
                self.capabilities.script_execution_integrity,
            filesystem_enforcement=self.capabilities.filesystem_enforcement,
            network_enforcement=self.capabilities.network_enforcement,
        )


def test_staged_success_publishes_exact_child_and_consumes_once(tmp_path, monkeypatch):
    plan, stage, target, _script = _staged_plan(tmp_path)
    calls = []
    phases = []
    original = run_plans.publication.publish_staged_batch
    original_claim_validator = run_plans._claim_validator

    def observed(child, **kwargs):
        calls.append((copy.deepcopy(child), kwargs))
        return original(child, **kwargs)

    def claim_validator(parent, claim, child, phase):
        phases.append(phase)
        return original_claim_validator(parent, claim, child, phase)

    monkeypatch.setattr(run_plans.publication, "publish_staged_batch", observed)
    monkeypatch.setattr(run_plans, "_claim_validator", claim_validator)
    provider = VerifiedObservedProvider()
    result = run_plans.apply_run_plan(
        plan, expected_plan_hash=plan["plan_sha256"], execution_provider=provider,
    )
    assert result["outcome"] == "success"
    assert target.read_text(encoding="utf-8") == "built"
    assert result["stage_transaction_id"]
    assert result["publication_transaction_id"]
    assert result["stage_transaction_id"] != result["publication_transaction_id"]
    child, kwargs = calls[0]
    assert child["parent"]["plan_sha256"] == plan["plan_sha256"]
    assert child["operations"][0] == {
        "number": 1, "staged": str(stage), "target": str(target),
        "staged_sha256": store.file_sha256(str(stage)),
        "target_before": plan["artifacts"][0]["target_before"],
        "validation": plan["artifacts"][0]["validation"],
    }
    assert kwargs["expected_plan_hash"] == child["plan_sha256"]
    assert kwargs["parent_plan"] == plan
    assert phases == ["pre_lock", "under_lock"]
    stage.unlink()
    target.write_text("old", encoding="utf-8")
    with pytest.raises(run_plans.RunPlanConsumed):
        run_plans.apply_run_plan(plan, execution_provider=provider)


def test_claim_is_consumed_after_process_failure(tmp_path):
    script = _writer(tmp_path, "raise SystemExit(7)\n")
    stage, target = tmp_path / "stage.bin", tmp_path / "target.bin"
    plan = run_plans.create_run_plan(
        [sys.executable, str(script)], mode="staged-publish", cwd=str(tmp_path),
        artifacts=[{"staged": str(stage), "target": str(target)}],
    )
    provider = VerifiedObservedProvider()
    result = run_plans.apply_run_plan(plan, execution_provider=provider)
    assert result["outcome"] == "process_failed"
    with pytest.raises(run_plans.RunPlanConsumed):
        run_plans.apply_run_plan(plan, execution_provider=provider)


class ReadOnlyProvider:
    capabilities = execution.ProviderCapabilities(
        isolation_modes=("read-only",), network_policies=("inherit",),
        filesystem_enforcement=True, network_enforcement=False,
        bounded_tail_capture=True, script_execution_integrity="verified-immutable",
        provider_identity="test-read-only",
    )

    def run(self, request):
        return execution.ExecutionResult(
            exit_code=0, stdout_tail="answer\n", stderr_tail="",
            capture_truncated=False, timed_out=False, duration_seconds=0.01,
            isolation_mode="read-only", network_policy="inherit",
            provider_identity=self.capabilities.provider_identity,
            script_execution_integrity=
                self.capabilities.script_execution_integrity,
            filesystem_enforcement=self.capabilities.filesystem_enforcement,
            network_enforcement=self.capabilities.network_enforcement,
        )


def test_capable_read_only_provider_executes_and_consumes(tmp_path):
    script = _writer(tmp_path, "print('unused by fake')\n")
    plan = run_plans.create_run_plan(
        [sys.executable, str(script)], mode="stdout-read-only", cwd=str(tmp_path),
        isolation="read-only", provider="test-read-only",
    )
    result = run_plans.apply_run_plan(plan, execution_provider=ReadOnlyProvider())
    assert result["outcome"] == "success"
    assert result["stdout_tail"] == "answer\n"
    with pytest.raises(run_plans.RunPlanConsumed):
        run_plans.apply_run_plan(plan, execution_provider=ReadOnlyProvider())


def test_provider_identity_mismatch_refuses_before_claim(tmp_path):
    plan, *_ = _staged_plan(tmp_path)
    provider = VerifiedObservedProvider()
    provider.capabilities = execution.ProviderCapabilities(
        isolation_modes=("observed",), network_policies=("inherit",),
        filesystem_enforcement=False, network_enforcement=False,
        bounded_tail_capture=True, script_execution_integrity="verified-immutable",
        provider_identity="different",
    )
    result = run_plans.apply_run_plan(plan, execution_provider=provider)
    assert result["error_code"] == "execution_provider_mismatch"
    assert result["execution_started"] is False
    assert result["claimed"] is False


def test_lying_provider_result_fails_closed_and_consumes(tmp_path):
    script = _writer(tmp_path, "print('fake')\n")
    plan = run_plans.create_run_plan(
        [sys.executable, str(script)], mode="stdout-read-only", cwd=str(tmp_path),
        isolation="read-only", provider="test-read-only",
    )

    class Lying(ReadOnlyProvider):
        def run(self, request):
            result = super().run(request)
            return execution.ExecutionResult(
                exit_code=result.exit_code, stdout_tail=result.stdout_tail,
                stderr_tail=result.stderr_tail,
                capture_truncated=result.capture_truncated,
                timed_out=result.timed_out, duration_seconds=result.duration_seconds,
                isolation_mode="observed", network_policy=result.network_policy,
                provider_identity=result.provider_identity,
                script_execution_integrity=result.script_execution_integrity,
                filesystem_enforcement=result.filesystem_enforcement,
                network_enforcement=result.network_enforcement,
            )

    result = run_plans.apply_run_plan(plan, execution_provider=Lying())
    assert result["operation_outcome"] == "environment_failure"
    assert result["error_code"] == "provider_result_invalid"
    assert result["execution_started"] is None
    assert result["process_outcome"] == "unknown"
    assert result["contract_outcome"] == "indeterminate"
    assert result["claimed"] is result["consumed"] is True


def test_duck_typed_fabricated_success_is_rejected_and_never_published(
        tmp_path, monkeypatch):
    plan, _stage, target, _script = _staged_plan(tmp_path)
    published = []

    class FabricatedSuccess:
        exit_code = 0
        stdout_tail = "forged"
        stderr_tail = ""
        capture_truncated = False
        timed_out = False
        duration_seconds = 0.0
        isolation_mode = "observed"
        network_policy = "inherit"
        process_outcome = "succeeded"
        execution_started = True
        fallback_performed = False
        provider_identity = "installed"
        script_execution_integrity = "verified-immutable"
        filesystem_enforcement = False
        network_enforcement = False

    class FabricatingProvider(VerifiedObservedProvider):
        def run(self, request):
            return FabricatedSuccess()

    monkeypatch.setattr(
        run_plans.publication, "publish_staged_batch",
        lambda *_args, **_kwargs: published.append(True),
    )
    result = run_plans.apply_run_plan(
        plan, execution_provider=FabricatingProvider(),
    )
    assert published == []
    assert target.read_text(encoding="utf-8") == "old"
    assert result["error_code"] == "provider_result_invalid"
    assert result["operation_outcome"] == "environment_failure"
    assert result["execution_started"] is None
    assert result["process_outcome"] == "unknown"
    assert result["contract_outcome"] == "indeterminate"
    assert result["claimed"] is result["consumed"] is True
    with pytest.raises(run_plans.RunPlanConsumed):
        run_plans.apply_run_plan(plan, execution_provider=FabricatingProvider())


def test_typed_result_with_inconsistent_success_metadata_fails_closed(tmp_path):
    script = _writer(tmp_path, "print('fake')\n")
    plan = run_plans.create_run_plan(
        [sys.executable, str(script)], mode="stdout-read-only", cwd=str(tmp_path),
        isolation="read-only", provider="test-read-only",
    )

    class Contradictory(ReadOnlyProvider):
        def run(self, request):
            result = execution.ExecutionResult(
                exit_code=0, stdout_tail="", stderr_tail="",
                capture_truncated=False, timed_out=False, duration_seconds=0.01,
                isolation_mode="read-only", network_policy="inherit",
                process_outcome="succeeded", execution_started=True,
                provider_identity=self.capabilities.provider_identity,
                script_execution_integrity="verified-immutable",
                filesystem_enforcement=True, network_enforcement=False,
            )
            # Model corruption after construction to exercise Node F's
            # defense-in-depth boundary independently of Node A validation.
            object.__setattr__(result, "exit_code", 9)
            return result

    result = run_plans.apply_run_plan(plan, execution_provider=Contradictory())
    assert result["error_code"] == "provider_result_invalid"
    assert result["operation_outcome"] == "environment_failure"
    assert result["execution_started"] is None
    assert result["claimed"] is result["consumed"] is True


def test_launched_then_generic_provider_error_preserves_unknown_provenance(tmp_path):
    plan, *_ = _staged_plan(tmp_path)
    launched = []

    class Broken(VerifiedObservedProvider):
        def run(self, request):
            launched.append(True)
            raise RuntimeError("unknown provider failure")

    result = run_plans.apply_run_plan(plan, execution_provider=Broken())
    assert launched == [True]
    assert result["execution_started"] is None
    assert result["executed"] is None
    assert result["process_outcome"] == "unknown"
    assert result["contract_outcome"] == "indeterminate"
    assert result["operation_outcome"] == "environment_failure"
    assert result["claimed"] is result["consumed"] is True


def test_typed_prelaunch_error_preserves_not_started(tmp_path):
    plan, *_ = _staged_plan(tmp_path)

    class RefusesBeforeLaunch(VerifiedObservedProvider):
        def run(self, request):
            raise execution.ExecutionError(
                "prelaunch refused",
                {"execution_started": False, "fallback_performed": False},
            )

    result = run_plans.apply_run_plan(
        plan, execution_provider=RefusesBeforeLaunch(),
    )
    assert result["execution_started"] is False
    assert result["process_outcome"] == "not_started"
    assert result["contract_outcome"] == "not_evaluated"
    assert result["operation_outcome"] == "environment_failure"
    assert result["claimed"] is result["consumed"] is True
