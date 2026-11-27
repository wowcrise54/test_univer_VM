"""Pairing of re-issued passports with the passport that replaced them."""

from app.mpvm.passport_records import plan_passport_replacements


def _row(internal_id, external_id="PT-1", package_id="pkg", package_version="1.0"):
    return {
        "internal_id": internal_id,
        "external_id": external_id,
        "package_id": package_id,
        "package_version": package_version,
    }


def test_exact_key_pairs_old_with_new_in_partial_refresh():
    pairs, ambiguous = plan_passport_replacements([_row("new")], [_row("old")], loose=False)
    assert pairs == [("old", "new")] and ambiguous == 0


def test_partial_refresh_does_not_guess_when_version_changed():
    pairs, ambiguous = plan_passport_replacements(
        [_row("new", package_version="2.0")], [_row("old")], loose=False
    )
    assert pairs == [] and ambiguous == 0


def test_complete_refresh_pairs_new_version_of_same_package():
    pairs, ambiguous = plan_passport_replacements(
        [_row("new", package_version="2.0")], [_row("old")], loose=True
    )
    assert pairs == [("old", "new")] and ambiguous == 0


def test_two_equal_successors_are_ambiguous_and_nothing_is_merged():
    pairs, ambiguous = plan_passport_replacements(
        [_row("new-1"), _row("new-2")], [_row("old")], loose=True
    )
    assert pairs == [] and ambiguous == 2


def test_distinct_packages_of_one_cve_are_not_merged():
    pairs, _ = plan_passport_replacements(
        [_row("new", package_id="other", package_version="9")],
        [_row("old", package_id="pkg")],
        loose=True,
    )
    assert pairs == []


def test_missing_package_data_falls_back_to_external_id_when_unique():
    pairs, _ = plan_passport_replacements(
        [_row("new", package_id=None, package_version=None)], [_row("old")], loose=True
    )
    assert pairs == [("old", "new")]


def test_several_stale_duplicates_fold_into_the_single_successor():
    pairs, ambiguous = plan_passport_replacements(
        [_row("new")],
        [_row("old-1"), _row("old-2", package_version="0.9")],
        loose=True,
    )
    assert sorted(pairs) == [("old-1", "new"), ("old-2", "new")] and ambiguous == 0


def test_each_version_pairs_with_its_own_successor():
    pairs, ambiguous = plan_passport_replacements(
        [_row("new-1", package_version="1.0"), _row("new-2", package_version="2.0")],
        [_row("old-1", package_version="1.0"), _row("old-2", package_version="2.0")],
        loose=True,
    )
    assert sorted(pairs) == [("old-1", "new-1"), ("old-2", "new-2")] and ambiguous == 0


def test_passport_present_in_both_lists_is_never_replaced_and_rows_without_external_id_are_skipped():
    pairs, _ = plan_passport_replacements(
        [_row("same"), _row("new-x", external_id=None)],
        [_row("same"), _row("old-x", external_id=None)],
        loose=True,
    )
    assert pairs == []
