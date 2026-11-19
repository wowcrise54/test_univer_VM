import pytest

from app.services.stale_scan_assets import unavailable_scan_ips


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
