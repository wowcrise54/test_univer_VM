from __future__ import annotations

import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main
from app.repositories.vulnerabilities import (
    CAPTURE_SNAPSHOT_SQL,
    VULNERABILITY_SEVERITIES,
    VulnerabilityAnalyticsRepository,
)
from app.services.vulnerabilities import VulnerabilityAnalyticsService


class FakeResult:
    def __init__(self, rows):
        self.rows = list(rows)

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, responses):
        self.responses = list(responses)
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=None):
        self.queries.append((str(sql), list(params or [])))
        return FakeResult(self.responses.pop(0))


def database_snapshot_rows(
    *,
    snapshot_id: int = 7,
    captured_at: datetime | None = None,
    trigger_kind: str = "asset_card_build",
    trigger_id: str = "job-7",
):
    captured = captured_at or datetime(2026, 7, 12, 8, tzinfo=UTC)
    rows = []
    for index, severity in enumerate(VULNERABILITY_SEVERITIES):
        rows.append(
            {
                "id": snapshot_id,
                "scope": "all_asset_cards",
                "trigger_kind": trigger_kind,
                "trigger_id": trigger_id,
                "captured_at": captured,
                "hosts_total": 4,
                "affected_hosts": 3,
                "findings": 12,
                "unique_vulnerabilities": 6,
                "unique_cves": 5,
                "high_risk_hosts": 2,
                "unrated_vulnerabilities": 1,
                "coverage_cards_total": 4,
                "coverage_cards_with_findings": 3,
                "coverage_truncated_groups": 1,
                "coverage_complete": False,
                "coverage_oldest_at": "2026-07-10T08:00:00+00:00",
                "coverage_freshest_at": "2026-07-12T08:00:00+00:00",
                "severity": severity,
                "severity_findings": index + 1,
                "severity_affected_hosts": 1,
                "severity_unique_vulnerabilities": 1,
            }
        )
    return rows


def service_snapshot(snapshot_id: int, captured_at: datetime, findings: int):
    return {
        "id": snapshot_id,
        "captured_at": captured_at,
        "totals": {
            "hosts_total": 3,
            "affected_hosts": 2,
            "findings": findings,
            "unique_vulnerabilities": 4,
            "unique_cves": 3,
            "high_risk_hosts": 1,
            "unrated_vulnerabilities": 0,
        },
        "by_severity": {
            severity: {
                "findings": findings if severity == "high" else 0,
                "affected_hosts": 1 if severity == "high" else 0,
                "unique_vulnerabilities": 1 if severity == "high" else 0,
            }
            for severity in VULNERABILITY_SEVERITIES
        },
        "coverage": {
            "cards_total": 3,
            "cards_with_findings": 2,
            "truncated_groups": 0,
            "complete": True,
            "oldest_at": "2026-07-01T00:00:00+00:00",
            "freshest_at": captured_at.isoformat(),
        },
    }


class SnapshotRepositoryTests(unittest.TestCase):
    def test_capture_is_atomic_and_idempotent_by_trigger(self):
        self.assertIn("inserted_severity AS", CAPTURE_SNAPSHOT_SQL)
        self.assertIn("ON CONFLICT (trigger_kind, trigger_id) DO NOTHING", CAPTURE_SNAPSHOT_SQL)

        connection = FakeConnection(
            [
                [{"id": 7}],
                [{"acquired": True}],
                [{"due": False}],
                database_snapshot_rows(),
            ]
        )
        repository = VulnerabilityAnalyticsRepository()
        with (
            patch("app.repositories.vulnerabilities.db.init_db"),
            patch("app.repositories.vulnerabilities.db.connect", return_value=connection),
        ):
            result = repository.capture_snapshot(
                trigger_kind="asset_card_build",
                trigger_id="job-7",
                captured_at=datetime(2026, 7, 12, 8, tzinfo=UTC),
            )

        self.assertTrue(result["created"])
        self.assertEqual(result["snapshot"]["totals"]["findings"], 12)
        self.assertEqual(result["snapshot"]["by_severity"]["critical"]["findings"], 1)
        self.assertFalse(result["snapshot"]["coverage"]["complete"])
        self.assertIn("pg_try_advisory_xact_lock", connection.queries[1][0])
        self.assertIn("date_trunc('day'", connection.queries[2][0])

    def test_existing_trigger_returns_original_snapshot_without_retention(self):
        connection = FakeConnection([[], database_snapshot_rows()])
        repository = VulnerabilityAnalyticsRepository()
        with (
            patch("app.repositories.vulnerabilities.db.init_db"),
            patch("app.repositories.vulnerabilities.db.connect", return_value=connection),
        ):
            result = repository.capture_snapshot(
                trigger_kind="asset_card_build",
                trigger_id="job-7",
            )

        self.assertFalse(result["created"])
        self.assertEqual(len(connection.queries), 2)
        self.assertNotIn("pg_try_advisory_xact_lock", connection.queries[1][0])

    def test_first_capture_of_utc_day_prunes_older_than_retention(self):
        connection = FakeConnection(
            [
                [{"id": 7}],
                [{"acquired": True}],
                [{"due": True}],
                [],
                database_snapshot_rows(),
            ]
        )
        repository = VulnerabilityAnalyticsRepository()
        with (
            patch("app.repositories.vulnerabilities.db.init_db"),
            patch("app.repositories.vulnerabilities.db.connect", return_value=connection),
        ):
            repository.capture_snapshot(
                trigger_kind="asset_card_build",
                trigger_id="job-7",
                captured_at=datetime(2026, 7, 12, 8, tzinfo=UTC),
            )

        delete_sql, delete_params = connection.queries[3]
        self.assertIn("DELETE FROM vulnerability_aggregate_snapshots", delete_sql)
        self.assertEqual(delete_params[2], 90)

    def test_migration_defines_baseline_and_cascading_severity_rows(self):
        migration = Path("migrations/versions/20260712_0005_vulnerability_trends.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("UNIQUE (trigger_kind, trigger_id)", migration)
        self.assertIn("ON DELETE CASCADE", migration)
        self.assertIn("'baseline', 'vulnerability-trends-v1'", migration)
        self.assertIn("ON CONFLICT (trigger_kind, trigger_id) DO NOTHING", migration)


class FakeTrendRepository:
    def __init__(self, snapshots):
        self.snapshots = snapshots
        self.calls = []

    def trend_snapshots(self, **filters):
        self.calls.append(filters)
        return self.snapshots


class VulnerabilityTrendServiceTests(unittest.TestCase):
    def test_daily_buckets_start_at_first_snapshot_and_carry_forward_gaps(self):
        start = datetime(2026, 7, 1, tzinfo=UTC)
        end = datetime(2026, 7, 4, 12, tzinfo=UTC)
        repository = FakeTrendRepository(
            [
                service_snapshot(1, datetime(2026, 7, 2, 10, tzinfo=UTC), 4),
                service_snapshot(2, datetime(2026, 7, 4, 8, tzinfo=UTC), 9),
            ]
        )
        service = VulnerabilityAnalyticsService(repository)  # type: ignore[arg-type]

        result = service.trends(from_at=start, to_at=end, bucket="day")

        self.assertEqual(
            [row["bucket_start"] for row in result["rows"]],
            [
                "2026-07-02T00:00:00+00:00",
                "2026-07-03T00:00:00+00:00",
                "2026-07-04T00:00:00+00:00",
            ],
        )
        self.assertEqual(
            [row["carried_forward"] for row in result["rows"]],
            [False, True, False],
        )
        self.assertEqual(result["rows"][1]["totals"]["findings"], 4)
        self.assertEqual(result["rows"][2]["totals"]["findings"], 9)

    def test_pre_range_snapshot_populates_first_bucket_as_carried_forward(self):
        repository = FakeTrendRepository(
            [service_snapshot(1, datetime(2026, 6, 30, 12, tzinfo=UTC), 4)]
        )
        service = VulnerabilityAnalyticsService(repository)  # type: ignore[arg-type]

        result = service.trends(
            from_at=datetime(2026, 7, 1, tzinfo=UTC),
            to_at=datetime(2026, 7, 2, 12, tzinfo=UTC),
        )

        self.assertEqual(len(result["rows"]), 2)
        self.assertTrue(all(row["carried_forward"] for row in result["rows"]))
        self.assertEqual(result["rows"][0]["snapshot_at"], "2026-06-30T12:00:00+00:00")

    def test_week_buckets_use_monday_utc_boundaries(self):
        repository = FakeTrendRepository(
            [
                service_snapshot(1, datetime(2026, 7, 2, 10, tzinfo=UTC), 4),
                service_snapshot(2, datetime(2026, 7, 10, 8, tzinfo=UTC), 7),
            ]
        )
        service = VulnerabilityAnalyticsService(repository)  # type: ignore[arg-type]

        result = service.trends(
            from_at=datetime(2026, 7, 1, tzinfo=UTC),
            to_at=datetime(2026, 7, 15, tzinfo=UTC),
            bucket="week",
        )

        self.assertEqual(
            [row["bucket_start"] for row in result["rows"]],
            [
                "2026-06-29T00:00:00+00:00",
                "2026-07-06T00:00:00+00:00",
                "2026-07-13T00:00:00+00:00",
            ],
        )
        self.assertEqual(result["rows"][-1]["totals"]["findings"], 7)
        self.assertTrue(result["rows"][-1]["carried_forward"])

    def test_more_than_ninety_days_is_rejected_before_query(self):
        repository = FakeTrendRepository([])
        service = VulnerabilityAnalyticsService(repository)  # type: ignore[arg-type]

        with self.assertRaisesRegex(ValueError, "90-day"):
            service.trends(
                from_at=datetime(2026, 1, 1, tzinfo=UTC),
                to_at=datetime(2026, 7, 1, tzinfo=UTC),
            )

        self.assertEqual(repository.calls, [])


class VulnerabilityTrendApiTests(unittest.TestCase):
    def test_openapi_exposes_trend_contract_and_iso_parameters(self):
        schema = main.app.openapi()
        operation = schema["paths"]["/api/vulnerabilities/trends"]["get"]
        self.assertEqual(operation["tags"], ["vulnerabilities"])
        self.assertEqual(
            {parameter["name"] for parameter in operation["parameters"]},
            {"from", "to", "bucket"},
        )

    def test_endpoint_forwards_parsed_range_to_service(self):
        service = main.CONTAINER.services.vulnerabilities
        payload = {
            "scope": "all_asset_cards",
            "from": "2026-07-01T00:00:00+00:00",
            "to": "2026-07-02T00:00:00+00:00",
            "bucket": "day",
            "retention_days": 90,
            "rows": [],
        }
        with patch.object(service, "trends", return_value=payload) as trends, patch.object(
            main.app_auth, "get_session_user", return_value={"id": 1, "role": "viewer"}
        ):
            response = TestClient(main.app).get(
                "/api/vulnerabilities/trends",
                params={
                    "from": "2026-07-01T00:00:00Z",
                    "to": "2026-07-02T00:00:00Z",
                    "bucket": "day",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), payload)
        trends.assert_called_once_with(
            from_at=datetime(2026, 7, 1, tzinfo=UTC),
            to_at=datetime(2026, 7, 2, tzinfo=UTC),
            bucket="day",
        )

    def test_invalid_range_is_returned_as_structured_422(self):
        service = main.CONTAINER.services.vulnerabilities
        with patch.object(service, "trends", side_effect=ValueError("range too large")), patch.object(
            main.app_auth, "get_session_user", return_value={"id": 1, "role": "viewer"}
        ):
            response = TestClient(main.app).get("/api/vulnerabilities/trends")

        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["detail"]["code"], "INVALID_RANGE")


if __name__ == "__main__":
    unittest.main()
