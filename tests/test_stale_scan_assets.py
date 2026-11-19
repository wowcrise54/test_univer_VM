from datetime import UTC, datetime

import pytest

from app.services.stale_scan_assets import stale_asset_id, unavailable_scan_ips


@pytest.mark.parametrize(
    ("jobs", "expected"),
    [
        ([{"errors": ["confirmed-no-route"]}], {"192.0.2.1"}),
        ([{"errors": ["timeout"]}], set()),
        ([{"errors": ["confirmed-no-route", "authentication"]}], set()),
        ([{"errors": ["confirmed-no-route"]}, {"status": "success", "errors": []}], set()),
    ],
)
def test_unavailable_requires_explicit_per_ip_evidence(jobs, expected):
    jobs = [
        {
            "id": str(index),
            "status": "finished",
            "runMode": "connectionCheck",
            "targets": ["192.0.2.1"],
            "connectionCheckResults": [{"status": "fail", **result}],
        }
        for index, result in enumerate(jobs)
    ]
    assert unavailable_scan_ips(jobs, {"confirmed-no-route"}) == expected


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({}, "asset-1"),
        ({"AuditTime": "2026-01-02T00:00:00Z"}, None),
        ({"PentestTime": "2026-01-02T00:01:00Z"}, None),
        ({"UpdateTime": "unknown"}, None),
        ({"AllAddresses": ["192.0.2.1", "192.0.2.2"]}, None),
    ],
)
def test_stale_asset_requires_old_timestamps_and_one_ip(changes, expected):
    row = {
        "AssetId": "asset-1",
        "IpAddress": "192.0.2.1",
        "AllAddresses": ["192.0.2.1"],
        "CreationTime": "2025-12-31T00:00:00Z",
        "UpdateTime": "2026-01-01T00:00:00Z",
        "AuditTime": None,
        "PentestTime": None,
        **changes,
    }
    assert stale_asset_id(row, "192.0.2.1", datetime(2026, 1, 2, tzinfo=UTC)) == expected
