"""Storage isolation must preserve recovery and avoid cross-class eviction."""
import json
import os
from pathlib import Path

import pytest

from core import archive_transactions as tx
from core import preimages, recovery_storage, retention, retention_policy, store


def policy(**settings):
    return retention_policy.resolve_retention_policy({
        "archive_max_bytes": 1_000_000,
        "archive_document_reserve_bytes": 500_000,
        "archive_media_max_bytes": 375_000,
        "archive_derived_max_bytes": 125_000,
        **settings,
    }, {})


def capture(path, cfg, size=80_000, value=b"x", **kwargs):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value * size)
    return store.archive_file(
        str(path), mode="copy", retention_class="mutation_preimage",
        retention_config=cfg, **kwargs,
    )


def test_standard_budget_guarantees_document_headroom():
    cfg = retention_policy.resolve_retention_policy({}, {})
    assert cfg.document_reserve_bytes == 2 * retention_policy.GIB
    assert cfg.media_max_bytes == 3 * retention_policy.GIB // 2
    assert cfg.derived_max_bytes == retention_policy.GIB // 2
    assert cfg.media_max_bytes + cfg.derived_max_bytes == cfg.max_bytes - cfg.document_reserve_bytes


@pytest.mark.parametrize("settings", [
    {"archive_document_reserve_bytes": 1_000_001},
    {"archive_media_max_bytes": 600_000},
    {"archive_derived_max_bytes": -1},
    {"archive_storage_rules": "renders"},
    {"archive_storage_rules": [{"pattern": "**/renders/**", "storage_class": "disposable"}]},
    {"archive_storage_rules": [{"pattern": "", "storage_class": "derived"}]},
])
def test_invalid_storage_policy_is_rejected(settings):
    with pytest.raises(retention_policy.RetentionPolicyError):
        policy(**settings)


def test_environment_storage_overrides_and_unlimited():
    cfg = retention_policy.resolve_retention_policy({}, {
        "AGW_ARCHIVE_MAX_BYTES": "1000",
        "AGW_ARCHIVE_MEDIA_MAX_BYTES": "300",
        "AGW_ARCHIVE_DERIVED_MAX_BYTES": "100",
    })
    assert cfg.document_reserve_bytes == 500
    assert cfg.media_max_bytes == 300
    assert cfg.derived_max_bytes == 100
    unlimited = retention_policy.resolve_retention_policy({"archive_max_bytes": 0}, {})
    assert not unlimited.separated
    assert unlimited.document_reserve_bytes == 0
    more_reserve = retention_policy.resolve_retention_policy({
        "archive_max_bytes": 1000, "archive_document_reserve_bytes": 800,
    }, {})
    assert more_reserve.media_max_bytes == 150
    assert more_reserve.derived_max_bytes == 50


@pytest.mark.parametrize("name,expected", [
    ("signed.PDF", "documents"), ("notes.md", "documents"),
    ("speech.wav", "media"), ("recording.MP4", "media"), ("portrait.png", "media"),
    ("render.mp4", "media"),  # A suggestive filename is not a derived declaration.
])
def test_builtin_accounting_classification(name, expected):
    assert recovery_storage.classify(name) == expected


def test_media_cannot_consume_document_reserve(tmp_path):
    cfg = policy()
    media = capture(tmp_path / "original.mp4", cfg, size=350_000)
    with pytest.raises(store.ArchiveCapacityError) as failure:
        capture(tmp_path / "second.wav", cfg)
    assert failure.value.details["storage_budget"] == "media"
    assert "archive_media_max_bytes" in str(failure.value)
    assert "document history" in str(failure.value)
    # The reserved space is still available for document recovery.
    document = capture(tmp_path / "signed.pdf", cfg, size=400_000)
    assert os.path.isfile(media["dest"])
    assert os.path.isfile(document["dest"])
    report = store.storage_report(cfg)
    assert report["classes"]["media"]["used_bytes"] == 350_000
    assert report["classes"]["documents"]["used_bytes"] == 400_000
    assert sum(row["used_bytes"] for row in report["classes"].values()) == report["total_bytes"]


def test_documents_can_borrow_unused_space(tmp_path):
    entry = capture(tmp_path / "large.pdf", policy(), size=700_000)
    assert os.path.isfile(entry["dest"])


def test_unclassified_bytes_cannot_consume_the_document_reserve(tmp_path):
    root = Path(store.agw_home()) / "archive"
    root.mkdir(parents=True)
    (root / "orphan.bin").write_bytes(b"o" * 50_000)
    cfg = policy(archive_storage_rules=[{"pattern": "**/renders/**", "storage_class": "derived"}])
    capture(tmp_path / "video.mp4", cfg, size=330_000)
    capture(tmp_path / "renders" / "output.mp4", cfg, size=110_000)
    with pytest.raises(store.ArchiveCapacityError) as failure:
        capture(tmp_path / "another.mp4", cfg, size=30_000)
    assert failure.value.details["storage_budget"] == "document_reserve"
    document = capture(tmp_path / "document.pdf", cfg, size=400_000)
    assert tx.entry_is_verified(store.agw_home(), document)


def test_document_pressure_does_not_evict_media(tmp_path):
    cfg = policy()
    old = capture(tmp_path / "video.mp4", cfg)
    capture(tmp_path / "video.mp4", cfg, value=b"y")
    with pytest.raises(store.ArchiveCapacityError):
        capture(tmp_path / "huge.pdf", cfg, size=900_000)
    assert os.path.isfile(old["dest"])


def test_media_pressure_reclaims_media_and_keeps_document_history(tmp_path):
    cfg = policy()
    doc_old = capture(tmp_path / "notes.pdf", cfg, size=15_000)
    doc_new = capture(tmp_path / "notes.pdf", cfg, size=15_000, value=b"n")
    media_old = capture(tmp_path / "video.mp4", cfg, size=140_000)
    media_new = capture(tmp_path / "video.mp4", cfg, size=140_000, value=b"v")
    media_last = capture(tmp_path / "video.mp4", cfg, size=140_000, value=b"w")
    assert not os.path.exists(media_old["dest"])
    for entry in (doc_old, doc_new, media_new, media_last):
        assert tx.entry_is_verified(store.agw_home(), entry)


def test_derived_rules_are_explicit_and_keep_original_protections(tmp_path):
    cfg = policy(archive_storage_rules=[
        {"pattern": "**/renders/**", "storage_class": "derived"},
    ])
    entry = capture(tmp_path / "renders" / "output.mp4", cfg, size=90_000)
    assert entry["storage_class"] == "derived"
    with pytest.raises(store.ArchiveCapacityError) as failure:
        capture(tmp_path / "renders" / "different.mp4", cfg, size=90_000)
    assert failure.value.details["storage_budget"] == "derived"
    assert tx.entry_is_verified(store.agw_home(), entry)
    normal = capture(tmp_path / "original.mp4", cfg, size=90_000)
    assert normal["storage_class"] == "media"
    report = store.storage_report(cfg)
    assert report["classes"]["derived"]["protected_or_unclassified_bytes"] == 90_000


def test_directory_snapshots_do_not_bypass_media_cap(tmp_path):
    folder = tmp_path / "mixed"
    folder.mkdir()
    (folder / "recording.mp4").write_bytes(b"v" * 400_000)
    with pytest.raises(store.ArchiveCapacityError) as failure:
        store.archive_file(str(folder), mode="copy", retention_class="manual_snapshot",
                           retention_config=policy())
    assert failure.value.details["storage_budget"] == "media"


def test_hook_aggregate_admission_uses_actual_classes(tmp_path):
    cfg = policy()
    stable = tmp_path / "original.mp4"
    capture(stable, cfg, size=350_000, policy_revision="revision")
    document = tmp_path / "signed.pdf"
    document.write_bytes(b"p" * 300_000)
    result = preimages.prepare([str(stable), str(document)], "Edit", 1_000_000,
                               policy_revision="revision", retention_config=cfg)
    assert result.ok, result.reason
    assert all(preimages.receipt_valid(receipt, "revision") for receipt in result.receipts)
    assert len(store.list_versions(str(stable))) == 1


def test_failed_mixed_batch_does_not_capture_document_first(tmp_path):
    cfg = policy()
    document = tmp_path / "notes.pdf"
    media = tmp_path / "large.mp4"
    document.write_bytes(b"p" * 30_000)
    media.write_bytes(b"m" * 400_000)
    result = preimages.prepare([str(document), str(media)], "Edit", 1_000_000,
                               policy_revision="revision", retention_config=cfg)
    assert not result.ok
    assert result.details["storage_budget"] == "media"
    assert store.list_versions(str(document)) == []
    assert store.list_versions(str(media)) == []


def test_scoped_plan_cannot_evict_another_bucket(tmp_path):
    from core import recovery_contracts
    cfg = policy(archive_min_protected_age_days=0, archive_inactive_collapse_age_days=0)
    old = capture(tmp_path / "notes.pdf", cfg, size=10_000)
    capture(tmp_path / "notes.pdf", cfg, size=10_000, value=b"n")
    plan = retention.build_plan(store.agw_home(), max_bytes=1, capacity_pressure=True)
    assert old["transaction_id"] in {c["transaction_id"] for c in plan["candidates"]}
    plan["storage_classes"] = ["media"]
    plan = recovery_contracts.bind_plan_hash(plan)
    with pytest.raises(retention.InvalidPlanError, match="outside its storage scope"):
        retention.apply_plan(store.agw_home(), plan, expected_plan_hash=plan["plan_sha256"])
    assert os.path.isfile(old["dest"])


def test_old_records_are_accounted_without_rewriting_and_restore(tmp_path):
    source = tmp_path / "legacy.wav"
    source.write_bytes(b"old exact bytes")
    dest = Path(store.agw_home()) / "archive" / "legacy.wav"
    dest.parent.mkdir(parents=True)
    entry = tx.create_archive(store.agw_home(), str(source), str(dest), "copy", 1)
    manifest = Path(store.agw_home()) / "transactions" / (entry["transaction_id"] + ".json")
    before = manifest.read_bytes()
    report = store.storage_report(policy())
    assert report["classes"]["media"]["used_bytes"] == len(b"old exact bytes")
    assert manifest.read_bytes() == before
    source.write_bytes(b"new")
    store.restore(str(source), overwrite=True, retention_config=policy())
    assert source.read_bytes() == b"old exact bytes"


def test_usage_cache_is_incremental_and_recovers_from_corruption(tmp_path, monkeypatch):
    cfg = policy()
    capture(tmp_path / "first.pdf", cfg, size=1000)
    real = retention.inventory
    def no_inventory(*args, **kwargs):
        raise AssertionError("routine below-water capture must use the class counter")
    with monkeypatch.context() as scoped:
        scoped.setattr(retention, "inventory", no_inventory)
        capture(tmp_path / "second.pdf", cfg, size=1000)
    cache = Path(store.agw_home()) / recovery_storage.CACHE_NAME
    cache.write_text("corrupt")
    capture(tmp_path / "third.pdf", cfg, size=1000)
    data = json.loads(cache.read_text())
    assert data["usage"]["documents"] == 3000
    assert real(store.agw_home())["complete"]


def test_zero_media_budget_refuses_growth_but_allows_verified_reuse(tmp_path):
    from dataclasses import replace
    cfg = policy()
    path = tmp_path / "source.mp4"
    entry = capture(path, cfg, size=10_000)
    disabled = replace(cfg, media_max_bytes=0)
    reused = store.archive_file(str(path), mode="copy", dedupe=True,
                                retention_class="mutation_preimage", retention_config=disabled)
    assert reused["transaction_id"] == entry["transaction_id"]
    with pytest.raises(store.ArchiveCapacityError) as failure:
        capture(tmp_path / "other.mp4", disabled, size=100)
    assert failure.value.details["maximum_bytes"] == 0
    assert failure.value.details["storage_budget"] == "media"


def test_policy_rules_do_not_reclassify_legacy_or_reused_copies(tmp_path):
    path = tmp_path / "renders" / "original.mp4"
    old = capture(path, policy(), size=20_000)
    cfg = policy(archive_storage_rules=[{"pattern": "**/renders/**", "storage_class": "derived"}])
    reused = store.archive_file(str(path), mode="copy", dedupe=True,
                                retention_class="mutation_preimage", retention_config=cfg)
    assert reused["transaction_id"] == old["transaction_id"]
    assert reused["storage_class"] == "media"
    new = capture(path, cfg, size=20_000, value=b"n")
    assert new["storage_class"] == "derived"
    assert store.storage_report(cfg)["classes"]["media"]["used_bytes"] == 20_000


def test_unknown_storage_classes_stay_protected(tmp_path):
    old = capture(tmp_path / "source.mp4", policy(), size=10_000)
    capture(tmp_path / "source.mp4", policy(), size=10_000, value=b"n")
    tx.update(store.agw_home(), old["transaction_id"], storage_class="future-class")
    plan = retention.build_plan(store.agw_home(), max_bytes=1, capacity_pressure=True)
    assert old["transaction_id"] not in {c["transaction_id"] for c in plan["candidates"]}


def test_hook_reuse_probe_honors_supplied_policy(tmp_path, monkeypatch):
    cfg = policy()
    source = tmp_path / "source.pdf"
    source.write_bytes(b"document")
    monkeypatch.setenv("AGW_ARCHIVE_MAX_BYTES", "invalid")
    result = preimages.prepare([str(source)], "Edit", 100_000,
                               policy_revision="revision", retention_config=cfg)
    assert result.ok, result.reason


def test_policy_file_rules_and_cli_reports(tmp_path, monkeypatch, capsys):
    import agw as cli
    import retention_config
    from core import miniyaml
    from types import SimpleNamespace

    root = tmp_path / "plugin"
    policies = root / "policies"
    policies.mkdir(parents=True)
    data = """settings:
  archive_max_bytes: 1000000
  archive_storage_rules:
    - pattern: '**/renders/**'
      storage_class: derived
"""
    (policies / "core.yaml").write_text(data)
    assert miniyaml.loads(data)["settings"]["archive_storage_rules"][0]["storage_class"] == "derived"
    cfg = retention_config.load(str(root))
    entry = capture(tmp_path / "renders" / "output.wav", cfg, size=10_000)
    monkeypatch.setattr(cli, "PLUGIN_ROOT", str(root))
    cli.cmd_status(SimpleNamespace(json=True, cwd="", stale_days=30))
    report = json.loads(capsys.readouterr().out)["storage"]
    assert report["classes"]["derived"]["used_bytes"] == 10_000
    assert report["classes"]["derived"]["largest"][0]["transaction_id"] == entry["transaction_id"]
    assert tx.entry_is_verified(store.agw_home(), entry)
