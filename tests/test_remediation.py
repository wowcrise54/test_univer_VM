from __future__ import annotations

import unittest
from datetime import UTC, date, datetime, timedelta
from unittest.mock import patch

from app.repositories.remediation import RemediationRepository
from app.services.remediation import RemediationService


class FakeRepository:
    def __init__(self) -> None:
        self.item = {
            "case_id": "case-1",
            "asset_id": "asset-1",
            "vulnerability_key": "cve:CVE-2026-1",
            "version": 3,
            "status": "open",
        }
        self.updates = []
        self.starts = []

    def update(self, case_id, changes, *, expected_version, comment):
        self.updates.append((case_id, changes, expected_version, comment))
        self.item = {**self.item, **changes, "version": expected_version + 1}
        return self.item

    def get(self, case_id):
        return self.item if case_id == "case-1" else None

    def start_for_finding(
        self,
        *,
        asset_id,
        vulnerability_key,
        assignee,
        due_at,
        comment,
        resume_exception,
    ):
        self.starts.append(
            {
                "asset_id": asset_id,
                "vulnerability_key": vulnerability_key,
                "assignee": assignee,
                "due_at": due_at,
                "comment": comment,
                "resume_exception": resume_exception,
            }
        )
        if (
            asset_id != self.item["asset_id"]
            or vulnerability_key != self.item["vulnerability_key"]
        ):
            raise LookupError("FINDING_NOT_FOUND")
        if (
            self.item["status"] in {"risk_accepted", "false_positive"}
            and not resume_exception
        ):
            raise ValueError("Explicit confirmation is required")
        if self.item["status"] == "in_progress" and assignee is None and due_at is None:
            return self.item
        self.item = {
            **self.item,
            "status": "in_progress",
            "assignee": assignee,
            "due_at": due_at,
            "version": self.item["version"] + 1,
        }
        return self.item

    def resolution_stats(self, *, days, recent_limit):
        return {"period_days": days, "recent_limit": recent_limit}

    def asset_ids(self):
        return []


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
        self.queries.append((sql, tuple(params or ())))
        if sql.lstrip().startswith("SET TRANSACTION"):
            return FakeResult([])
        return FakeResult(self.responses.pop(0))


class RemediationServiceTests(unittest.TestCase):
    def setUp(self):
        self.repository = FakeRepository()
        self.service = RemediationService(self.repository, stale_days=7)  # type: ignore[arg-type]

    def test_resolved_status_requires_scan_evidence(self):
        with self.assertRaisesRegex(ValueError, "complete refresh"):
            self.service.update("case-1", {"expected_version": 3, "status": "resolved"})

    def test_risk_acceptance_requires_reason_and_future_expiration(self):
        with self.assertRaisesRegex(ValueError, "requires a reason"):
            self.service.update("case-1", {"expected_version": 3, "status": "risk_accepted"})
        future = (datetime.now(UTC) + timedelta(days=10)).isoformat()
        item = self.service.update(
            "case-1",
            {"expected_version": 3, "status": "risk_accepted", "risk_reason": "Компенсирующая мера", "risk_expires_at": future},
        )
        self.assertEqual(item["status"], "risk_accepted")
        self.assertEqual(self.repository.updates[-1][2], 3)

    def test_bulk_update_uses_current_version(self):
        result = self.service.bulk_update(["case-1", "case-1", "missing"], {"status": "in_progress"})
        self.assertEqual(result["updated_count"], 1)
        self.assertEqual(self.repository.updates[0][2], 3)

    def test_start_for_finding_reconciles_and_moves_case_to_in_progress(self):
        result = self.service.start_for_finding(
            asset_id=" asset-1 ",
            vulnerability_selector=" cve:CVE-2026-1 ",
        )

        self.assertEqual(result["status"], "in_progress")
        self.assertEqual(self.repository.starts[0]["asset_id"], "asset-1")
        self.assertEqual(
            self.repository.starts[0]["vulnerability_key"],
            "cve:CVE-2026-1",
        )
        self.assertIn("Уязвимости", self.repository.starts[0]["comment"])

    def test_start_for_finding_is_idempotent_for_active_case(self):
        self.repository.item["status"] = "in_progress"

        result = self.service.start_for_finding(
            asset_id="asset-1",
            vulnerability_selector="cve:CVE-2026-1",
        )

        self.assertEqual(result["status"], "in_progress")
        self.assertEqual(self.repository.updates, [])

    def test_start_for_finding_requires_confirmation_to_remove_exception(self):
        self.repository.item["status"] = "risk_accepted"

        with self.assertRaisesRegex(ValueError, "Explicit confirmation"):
            self.service.start_for_finding(
                asset_id="asset-1",
                vulnerability_selector="cve:CVE-2026-1",
            )

        result = self.service.start_for_finding(
            asset_id="asset-1",
            vulnerability_selector="cve:CVE-2026-1",
            resume_exception=True,
        )
        self.assertEqual(result["status"], "in_progress")

    def test_start_for_finding_rejects_unknown_host_finding_pair(self):
        with self.assertRaises(LookupError):
            self.service.start_for_finding(
                asset_id="missing",
                vulnerability_selector="cve:CVE-2026-1",
            )

    def test_resolution_stats_forwards_period_and_recent_limit(self):
        result = self.service.resolution_stats(days=90, recent_limit=20)
        self.assertEqual(result, {"period_days": 90, "recent_limit": 20})


class RemediationRepositoryTests(unittest.TestCase):
    def test_start_for_finding_locks_and_updates_only_the_current_pair(self):
        finding = {
            "vulnerability_key": "cve:CVE-2026-1",
            "title": "Example",
            "cve": "CVE-2026-1",
            "severity": "critical",
            "cvss_score": 9.8,
            "passport_internal_id": None,
        }
        current = {
            "case_id": "case-1",
            "asset_id": "asset-1",
            "vulnerability_key": "cve:CVE-2026-1",
            "status": "open",
            "version": 3,
        }
        updated = {**current, "status": "in_progress", "version": 4}
        connection = FakeConnection([[finding], [current], [updated], []])
        repository = RemediationRepository()
        expected = {**updated, "events": []}
        with patch(
            "app.repositories.remediation.db.connect",
            return_value=connection,
        ), patch.object(repository, "get", return_value=expected):
            result = repository.start_for_finding(
                asset_id="asset-1",
                vulnerability_key="cve:CVE-2026-1",
                assignee=None,
                due_at=None,
                comment="Started from vulnerabilities",
                resume_exception=False,
            )

        self.assertEqual(result["status"], "in_progress")
        self.assertEqual(
            connection.queries[0][1],
            ("asset-1", "cve:CVE-2026-1"),
        )
        self.assertIn("FOR UPDATE", connection.queries[1][0])
        self.assertIn("WHERE case_id = %s", connection.queries[2][0])
        self.assertNotIn(
            "SELECT * FROM remediation_cases WHERE asset_id=%s FOR UPDATE",
            "\n".join(query for query, _params in connection.queries),
        )

    def test_start_for_finding_rejects_an_absent_current_finding(self):
        connection = FakeConnection([[]])
        repository = RemediationRepository()
        with patch(
            "app.repositories.remediation.db.connect",
            return_value=connection,
        ), self.assertRaises(LookupError):
            repository.start_for_finding(
                asset_id="asset-1",
                vulnerability_key="cve:CVE-2026-1",
                assignee=None,
                due_at=None,
                comment=None,
                resume_exception=False,
            )

    def test_resolution_stats_uses_one_snapshot_and_zero_filled_utc_days(self):
        confirmed_at = datetime(2026, 7, 24, 8, tzinfo=UTC)
        connection = FakeConnection(
            [
                [
                    {
                        "confirmed_resolutions": 3,
                        "resolved_cases": 2,
                        "resolved_hosts": 2,
                        "resolved_vulnerabilities": 1,
                        "currently_resolved": 1,
                        "mean_time_to_resolve_days": 2.5,
                    }
                ],
                [
                    {
                        "severity": "critical",
                        "confirmed_resolutions": 2,
                        "resolved_cases": 1,
                    }
                ],
                [
                    {
                        "bucket_start": date(2026, 7, 23),
                        "confirmed_resolutions": 0,
                        "resolved_cases": 0,
                        "resolved_hosts": 0,
                    },
                    {
                        "bucket_start": date(2026, 7, 24),
                        "confirmed_resolutions": 3,
                        "resolved_cases": 2,
                        "resolved_hosts": 2,
                    },
                ],
                [
                    {
                        "case_id": "case-1",
                        "asset_id": "asset-1",
                        "vulnerability_key": "cve:CVE-2026-1",
                        "status": "resolved",
                        "severity": "high",
                        "resolution_severity": "critical",
                        "resolution_confirmed_at": confirmed_at,
                        "display_name": None,
                        "ip_address": None,
                        "fqdn": None,
                        "overdue": False,
                        "near_due": False,
                    }
                ],
            ]
        )
        repository = RemediationRepository()
        with patch(
            "app.repositories.remediation.db.connect",
            return_value=connection,
        ):
            result = repository.resolution_stats(days=30, recent_limit=20)

        self.assertEqual(result["confirmed_resolutions"], 3)
        self.assertEqual(result["currently_resolved"], 1)
        self.assertEqual(result["trend"][0]["confirmed_resolutions"], 0)
        self.assertEqual(
            result["recent"][0]["resolution_confirmed_at"],
            confirmed_at.isoformat(),
        )
        sql = "\n".join(query for query, _params in connection.queries)
        self.assertIn("REPEATABLE READ", sql)
        self.assertIn("generate_series", sql)
        self.assertIn("AT TIME ZONE 'UTC'", sql)
        self.assertIn("LEFT JOIN asset_cards", sql)


class RemediationApiTests(unittest.TestCase):
    def test_start_endpoint_forwards_exact_host_finding_pair(self):
        from fastapi.testclient import TestClient

        from app import main

        service = main.CONTAINER.services.remediation
        item = {
            "case_id": "case-1",
            "asset_id": "asset-1",
            "vulnerability_key": "cve:CVE-2026-1",
            "status": "in_progress",
        }
        with patch.object(
            service,
            "start_for_finding",
            return_value=item,
        ) as start, patch.object(
            main.app_auth,
            "get_session_user",
            return_value={"id": 1, "role": "operator"},
        ):
            response = TestClient(main.app).post(
                "/api/remediation/cases/start",
                json={
                    "asset_id": "asset-1",
                    "vulnerability_selector": "cve:CVE-2026-1",
                    "resume_exception": True,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "in_progress")
        start.assert_called_once_with(
            asset_id="asset-1",
            vulnerability_selector="cve:CVE-2026-1",
            assignee=None,
            due_at=None,
            comment=None,
            resume_exception=True,
        )

    def test_openapi_exposes_start_and_resolution_statistics(self):
        from app import main

        schema = main.app.openapi()
        self.assertIn("/api/remediation/cases/start", schema["paths"])
        self.assertIn("/api/remediation/resolution-stats", schema["paths"])


if __name__ == "__main__":
    unittest.main()
