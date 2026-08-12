import pytest

from core import retention_policy as rp


def test_product_defaults_are_bounded_and_derive_watermarks():
    policy = rp.resolve_retention_policy({}, {})
    assert policy.max_bytes == 4 * rp.GIB
    assert policy.high_water_bytes == policy.max_bytes * 90 // 100
    assert policy.low_water_bytes == policy.max_bytes * 80 // 100
    assert policy.min_protected_age_days == 7
    assert policy.inactive_collapse_age_days == 30
    assert policy.max_candidates == 256
    assert policy.max_reclaim_bytes == rp.GIB
    assert policy.unlimited is False


def test_env_overrides_policy_and_canonical_policy_overrides_legacy():
    policy = rp.resolve_retention_policy(
        {"archive_max_bytes": 2000, "archive_max_warn_gb": 99},
        {"AGW_ARCHIVE_MAX_BYTES": "1000"},
    )
    assert policy.max_bytes == 1000
    assert policy.high_water_bytes == 900
    assert dict(policy.sources)["max_bytes"] == "env:AGW_ARCHIVE_MAX_BYTES"

    policy = rp.resolve_retention_policy(
        {"archive_max_bytes": 2000, "archive_max_warn_gb": "invalid"}, {}
    )
    assert policy.max_bytes == 2000


def test_legacy_gib_setting_is_preserved_when_canonical_is_absent():
    policy = rp.resolve_retention_policy({"archive_max_warn_gb": "3"}, {})
    assert policy.max_bytes == 3 * rp.GIB
    assert dict(policy.sources)["max_bytes"] == \
        "legacy-policy:archive_max_warn_gb"


def test_explicit_unlimited_disables_watermarks_and_pruning():
    policy = rp.resolve_retention_policy(
        {"archive_max_bytes": 0}, {"AGW_ARCHIVE_MAX_BYTES": "0"}
    )
    state = rp.classify_retention_state(policy, 100 * rp.GIB)
    assert policy.unlimited
    assert policy.high_water_bytes == policy.low_water_bytes == 0
    assert state.classification == rp.RetentionClassification.UNLIMITED
    assert state.bytes_until_capacity is None
    assert state.prune_recommended is False
    assert state.reclaim_target_bytes == 0


@pytest.mark.parametrize("value", [-1, "-1"])
def test_negative_values_fail_closed_with_stable_details(value):
    with pytest.raises(rp.RetentionPolicyError) as raised:
        rp.resolve_retention_policy({"archive_max_bytes": value}, {})
    assert raised.value.error_code == "retention_value_negative"
    assert raised.value.details["field"] == "archive_max_bytes"
    assert raised.value.details["source"] == "policy:archive_max_bytes"


@pytest.mark.parametrize("value", [True, 1.5, "1.5", "", object()])
def test_noninteger_values_fail_closed(value):
    with pytest.raises(rp.RetentionPolicyError) as raised:
        rp.resolve_retention_policy({}, {"AGW_ARCHIVE_MAX_BYTES": value})
    assert raised.value.error_code == "retention_value_not_integer"
    assert raised.value.details["field"] == "archive_max_bytes"


def test_invalid_threshold_and_age_order_have_stable_codes():
    with pytest.raises(rp.RetentionPolicyError) as threshold:
        rp.resolve_retention_policy({
            "archive_max_bytes": 100,
            "archive_low_water_bytes": 91,
            "archive_high_water_bytes": 90,
        }, {})
    assert threshold.value.error_code == "retention_threshold_invalid"
    assert threshold.value.details == {
        "max_bytes": 100, "high_water_bytes": 90, "low_water_bytes": 91,
    }

    with pytest.raises(rp.RetentionPolicyError) as ages:
        rp.resolve_retention_policy({
            "archive_min_protected_age_days": 31,
            "archive_inactive_collapse_age_days": 30,
        }, {})
    assert ages.value.error_code == "retention_age_order_invalid"


@pytest.mark.parametrize("field,value,maximum", [
    ("archive_max_candidates", 257, 256),
    ("archive_max_reclaim_bytes", rp.GIB + 1, rp.GIB),
    ("archive_max_candidates", 0, 256),
])
def test_per_pass_safety_limits_fail_closed(field, value, maximum):
    with pytest.raises(rp.RetentionPolicyError) as raised:
        rp.resolve_retention_policy({field: value}, {})
    assert raised.value.error_code == "retention_limit_invalid"
    assert raised.value.details["maximum"] == maximum


def test_threshold_arithmetic_and_state_classifications():
    policy = rp.resolve_retention_policy({
        "archive_max_bytes": 1000,
        "archive_max_reclaim_bytes": 75,
    }, {})
    cases = [
        (0, rp.RetentionClassification.BELOW_LOW_WATER, False, 0),
        (799, rp.RetentionClassification.BELOW_LOW_WATER, False, 0),
        (800, rp.RetentionClassification.BETWEEN_WATERMARKS, False, 0),
        (899, rp.RetentionClassification.BETWEEN_WATERMARKS, False, 0),
        (900, rp.RetentionClassification.HIGH_WATER, True, 75),
        (1000, rp.RetentionClassification.HIGH_WATER, True, 75),
        (1001, rp.RetentionClassification.OVER_CAPACITY, True, 75),
    ]
    for current, classification, prune, reclaim in cases:
        state = rp.classify_retention_state(policy, current)
        assert state.classification == classification
        assert state.prune_recommended is prune
        assert state.reclaim_target_bytes == reclaim
    over = rp.classify_retention_state(policy, 1001)
    assert over.over_capacity_bytes == 1
    assert over.bytes_until_high_water == 0
    assert over.bytes_until_capacity == 0


def test_state_rejects_invalid_current_bytes():
    policy = rp.resolve_retention_policy({}, {})
    with pytest.raises(rp.RetentionPolicyError) as raised:
        rp.classify_retention_state(policy, -1)
    assert raised.value.error_code == "retention_value_negative"
    assert raised.value.details["field"] == "current_bytes"


def test_serialized_contracts_are_typed_and_stable():
    policy = rp.resolve_retention_policy({}, {})
    state = rp.classify_retention_state(policy, policy.high_water_bytes)
    assert policy.as_dict()["schema"] == "agw.retention-policy/v1"
    data = state.as_dict()
    assert data["schema"] == "agw.retention-state/v1"
    assert data["classification"] == "high_water"
    assert data["capacity_exceeded"] is False
