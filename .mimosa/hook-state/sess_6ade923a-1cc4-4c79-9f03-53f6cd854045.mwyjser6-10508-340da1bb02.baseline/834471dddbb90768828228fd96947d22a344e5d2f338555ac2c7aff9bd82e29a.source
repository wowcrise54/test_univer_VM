import pytest

from app.services.passport_snapshot import validate_full_catalog


def row(identifier):
    return {"@VulnerPassport": {"internalId": identifier}}


@pytest.mark.parametrize("records,summary", [
    ([], {"reportedTotal": None, "batches": []}),
    ([row("p1")], {"reportedTotal": 2, "batches": [{"reported_total": 2}]}),
    ([row("p1"), row("p1")], {"reportedTotal": 2, "batches": [{"reported_total": 2}]}),
    ([{}], {"reportedTotal": 1, "batches": [{"reported_total": 1}]}),
    ([row("p1")], {"reportedTotal": 1, "batches": [{"reported_total": 2}, {"reported_total": 1}]}),
    ([row("p1")], {"reportedTotal": 1, "batches": "invalid"}),
    ([row("p1")], {"reportedTotal": True}),
    ([row("p1")], {"reportedTotal": -1}),
    ([row("p1")], {"reportedTotal": "1"}),
    ([row("p1")], {"reportedTotal": 1, "batches": [{"reported_total": 2}]}),
    ([None], {"reportedTotal": 1}),
])
def test_invalid_full_catalog_is_rejected(records, summary):
    with pytest.raises(ValueError):
        validate_full_catalog(records, summary)


@pytest.mark.parametrize("records,summary", [
    ([], {"reportedTotal": 0, "batches": [{"reported_total": 0}]}),
    ([row("p1")], {"reportedTotal": 1, "batches": [{"reported_total": 1}]}),
    ([row("p1")], {"reportedTotal": None, "batches": [{"reported_total": None}]}),
])
def test_verified_or_nonempty_exhausted_catalog_is_accepted(records, summary):
    validate_full_catalog(records, summary)


def test_nonempty_catalog_with_unknown_total_allows_current_api_contract():
    validate_full_catalog([row("p1"), row("p2")], {"reportedTotal": None, "batches": []})


def test_duplicate_ids_are_rejected_before_any_deduplication():
    with pytest.raises(ValueError, match="duplicate"):
        validate_full_catalog([row("p1"), row("p1")], {"reportedTotal": None, "batches": []})


@pytest.mark.parametrize("summary,verified", [
    ({"reportedTotal": None, "batches": []}, False),
    ({"reportedTotal": None, "batches": [{"reported_total": None}]}, False),
    ({"reportedTotal": 1}, False),
    ({"reportedTotal": 1, "batches": [{"reported_total": None}, {"reported_total": 1}]}, False),
    ({"reportedTotal": 1, "batches": [{"reported_total": 1}]}, True),
])
def test_only_fully_verified_pagination_allows_replacements(summary, verified):
    assert validate_full_catalog([row("p1")], summary) is verified