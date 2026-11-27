from scripts.seed_scale import (
    asset_id_for,
    asset_node_row,
    counts_for,
    finding_id_for,
    passport_id_for,
    passport_index_for_finding,
    resume_index_from_prefix,
)


def test_large_profile_has_requested_counts_and_fixed_foreign_key_mapping():
    counts = counts_for("large")
    assert counts == {"assets": 500, "passports": 500_000, "findings": 1_000_000}
    assert passport_index_for_finding(0) == 0
    assert passport_index_for_finding(1) == 0
    assert passport_index_for_finding(2) == 1
    assert asset_id_for(0, counts) == asset_id_for(1999, counts)
    assert asset_id_for(2000, counts) != asset_id_for(1999, counts)
    assert finding_id_for(42) == finding_id_for(42)
    assert passport_id_for(42) == passport_id_for(42)


def test_small_profile_preserves_the_same_ratios_for_fast_docker_tests():
    counts = counts_for("small")
    assert counts == {"assets": 2, "passports": 10, "findings": 20}
    assert all(passport_index_for_finding(i) == i // 2 for i in range(counts["findings"]))


def test_resume_accepts_only_a_deterministic_contiguous_prefix():
    assert resume_index_from_prefix(0, None, None, 10, passport_id_for) == 0
    assert resume_index_from_prefix(5, passport_id_for(0), passport_id_for(4), 10, passport_id_for) == 5
    assert resume_index_from_prefix(10, passport_id_for(0), passport_id_for(9), 10, passport_id_for) == 10
    try:
        resume_index_from_prefix(5, passport_id_for(0), passport_id_for(5), 10, passport_id_for)
    except ValueError:
        pass
    else:
        raise AssertionError("non-prefix partial load must require an explicit clean")


def test_each_large_asset_has_a_normalized_root_node_to_prevent_legacy_hydration():
    node = asset_node_row(0, counts_for("small"))
    assert node["asset_id"] == "scale-demo-asset-0000"
    assert node["path"] == "asset"
    assert node["node_json"]["objectId"] == node["asset_id"]
    assert node["data"]["hostname"] == "scale-linux-0001"
