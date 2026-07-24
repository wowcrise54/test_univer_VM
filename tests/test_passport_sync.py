from __future__ import annotations

import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import BackgroundTasks
from fastapi import HTTPException

from app import db
from app import main
from app.mpvm_client import TRENDING_VULNERABILITY_PDQL


class FakePassportClient:
    delay = 0.03
    active = 0
    max_active = 0
    lock = threading.Lock()

    def __init__(self, auth) -> None:
        self.auth = auth

    def get_vulnerability_passport(self, _token: str, passport_id: str):
        with self.lock:
            type(self).active += 1
            type(self).max_active = max(type(self).max_active, type(self).active)
        try:
            time.sleep(self.delay)
            return {"name": f"Passport {passport_id}"}
        finally:
            with self.lock:
                type(self).active -= 1


class PassportDetailWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        FakePassportClient.active = 0
        FakePassportClient.max_active = 0
        self.job = {"job_id": "job-1", "status": "queued", "loaded_count": 0, "failed_count": 0}
        self.batch_sizes: list[int] = []
        self.final_status = None

    def start_job(self, _job_id: str):
        self.job["status"] = "running"
        return dict(self.job)

    def save_batch(self, _job_id: str, *, details, errors):
        self.batch_sizes.append(len(details) + len(errors))
        self.job["loaded_count"] += len(details)
        self.job["failed_count"] += len(errors)
        return dict(self.job)

    def get_job(self, _job_id: str):
        return dict(self.job)

    def finish_job(self, _job_id: str, *, status: str, message=None):
        self.final_status = status
        self.job.update(status=status, message=message)
        return dict(self.job)

    def run_worker(self, internal_ids, cancel_event=None):
        with (
            patch.object(main, "MpVmClient", FakePassportClient),
            patch.object(main.db, "start_vulnerability_passport_detail_job", side_effect=self.start_job),
            patch.object(main.db, "save_vulnerability_passport_detail_job_batch", side_effect=self.save_batch),
            patch.object(main.db, "get_vulnerability_passport_detail_job", side_effect=self.get_job),
            patch.object(main.db, "reconcile_vulnerability_passport_detail_job_links") as reconcile_links,
            patch.object(main.db, "finish_vulnerability_passport_detail_job", side_effect=self.finish_job),
        ):
            main.run_vulnerability_passport_detail_job(
                job_id="job-1",
                auth=SimpleNamespace(),
                token="token",
                internal_ids=internal_ids,
                cancel_event=cancel_event or threading.Event(),
                workers=10,
                batch_size=20,
            )
        self.reconcile_links_calls = reconcile_links.call_count

    def test_worker_caps_concurrency_and_is_at_least_five_times_faster(self):
        internal_ids = [f"passport-{index}" for index in range(100)]
        started = time.perf_counter()
        self.run_worker(internal_ids)
        elapsed = time.perf_counter() - started

        self.assertEqual(self.final_status, "completed")
        self.assertEqual(self.job["loaded_count"], 100)
        self.assertLessEqual(FakePassportClient.max_active, 10)
        self.assertGreaterEqual(FakePassportClient.max_active, 5)
        self.assertTrue(all(size <= 20 for size in self.batch_sizes))
        self.assertEqual(self.reconcile_links_calls, 1)
        self.assertLess(elapsed, (len(internal_ids) * FakePassportClient.delay) / 5)

    def test_cancel_stops_scheduling_new_passports(self):
        cancel_event = threading.Event()
        worker = threading.Thread(
            target=self.run_worker,
            args=([f"passport-{index}" for index in range(1000)], cancel_event),
        )
        worker.start()
        time.sleep(0.08)
        cancel_event.set()
        worker.join(timeout=5)

        self.assertFalse(worker.is_alive())
        self.assertEqual(self.final_status, "cancelled")
        self.assertLess(self.job["loaded_count"], 1000)
        self.assertLessEqual(FakePassportClient.max_active, 10)

    def test_individual_errors_do_not_stop_the_job(self):
        original_get = FakePassportClient.get_vulnerability_passport

        def get_with_errors(client, token, passport_id):
            if passport_id.endswith("-error"):
                raise RuntimeError("remote error")
            return original_get(client, token, passport_id)

        internal_ids = [f"passport-{index}" for index in range(20)] + [f"passport-{index}-error" for index in range(5)]
        with patch.object(FakePassportClient, "get_vulnerability_passport", get_with_errors):
            self.run_worker(internal_ids)

        self.assertEqual(self.final_status, "completed_with_errors")
        self.assertEqual(self.job["loaded_count"], 20)
        self.assertEqual(self.job["failed_count"], 5)


class PassportQueryTests(unittest.TestCase):
    def test_trending_pdql_matches_the_current_trend_contract(self):
        expected = (
            "filter((VulnerPassport.IsTrend = true)) | "
            "select(@VulnerPassport, VulnerPassport.Score, "
            "VulnerPassport.Description, VulnerPassport.IssueTime, "
            "VulnerPassport.IsTrendSince, "
            "VulnerPassport.AffectedComponents.Vendor, "
            "compact(VulnerPassport.AffectedComponents.Name)) | "
            "sort(VulnerPassport.IsTrendSince DESC)"
        )

        self.assertEqual(
            " ".join(TRENDING_VULNERABILITY_PDQL.split()),
            expected,
        )

    def test_trending_record_normalizes_dashboard_metadata(self):
        record = {
            "@VulnerPassport": {
                "internalId": "passport-trend-1",
                "id": "CVE-2026-58644",
                "name": "SharePoint remote code execution",
                "severityRating": "critical",
            },
            "VulnerPassport.Score": Decimal("9.8"),
            "VulnerPassport.Description": "Remote code execution in SharePoint Server.",
            "VulnerPassport.IssueTime": "2026-07-10T08:00:00Z",
            "VulnerPassport.IsTrendSince": "2026-07-16T13:00:00Z",
            "VulnerPassport.AffectedComponents.Vendor": [
                "Microsoft",
                "Microsoft",
                "",
            ],
            "compact(VulnerPassport.AffectedComponents.Name)": {
                "data": [
                    {"displayName": "Microsoft SharePoint Server"},
                    {"name": "Windows"},
                    {"displayName": "Microsoft SharePoint Server"},
                ]
            },
        }

        normalized = main.normalize_trending_vulnerability_record(record)

        self.assertEqual(normalized["internal_id"], "passport-trend-1")
        self.assertEqual(normalized["external_id"], "CVE-2026-58644")
        self.assertEqual(normalized["name"], "SharePoint remote code execution")
        self.assertEqual(normalized["severity"], "critical")
        self.assertEqual(normalized["score"], Decimal("9.8"))
        self.assertEqual(
            normalized["description"],
            "Remote code execution in SharePoint Server.",
        )
        self.assertEqual(normalized["issue_time"], "2026-07-10T08:00:00Z")
        self.assertEqual(
            normalized["is_trend_since"],
            "2026-07-16T13:00:00Z",
        )
        self.assertEqual(normalized["vendors"], ["Microsoft"])
        self.assertEqual(
            normalized["affected_components"],
            ["Microsoft SharePoint Server", "Windows"],
        )
        self.assertEqual(normalized["raw_record"], record)

    def test_expanded_trend_rows_merge_vendor_and_component_values(self):
        base = {
            "internal_id": "passport-trend-1",
            "is_trend": True,
            "name": "SharePoint remote code execution",
            "vendors": ["Microsoft"],
            "affected_components": ["SharePoint Server"],
            "cves": [],
        }

        merged = main.merge_trending_vulnerability_records(
            [
                base,
                {
                    **base,
                    "vendors": ["Microsoft", "Contoso"],
                    "affected_components": ["Windows"],
                },
            ]
        )

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["vendors"], ["Microsoft", "Contoso"])
        self.assertEqual(
            merged[0]["affected_components"],
            ["SharePoint Server", "Windows"],
        )

    def test_passport_sync_requires_manage_permission(self):
        self.assertEqual(
            main.app_auth.required_permission(
                "POST", "/api/vulnerability-passports/query"
            ),
            "passports.manage",
        )
        self.assertEqual(
            main.app_auth.required_permission(
                "GET", "/api/vulnerability-passports/local"
            ),
            "passports.read",
        )

    def test_unverified_empty_trend_response_preserves_the_previous_snapshot(self):
        client = SimpleNamespace(
            create_pdql_token=lambda *_args, **_kwargs: "trend-token"
        )
        with (
            patch.object(
                main,
                "fetch_asset_grid_records",
                return_value=([], {"recordCount": 0, "reportedTotal": None}),
            ),
            patch.object(
                main.db, "replace_vulnerability_passport_trends"
            ) as replace,
        ):
            with self.assertRaisesRegex(ValueError, "previous snapshot was preserved"):
                main.sync_trending_vulnerability_passports(
                    client=client,
                    token="token",
                    utc_offset="+05:00",
                    batch_size=5000,
                    reconcile_links=False,
                )

        replace.assert_not_called()

    def test_verified_empty_trend_response_clears_the_current_snapshot(self):
        client = SimpleNamespace(
            create_pdql_token=lambda *_args, **_kwargs: "trend-token"
        )
        with (
            patch.object(
                main,
                "fetch_asset_grid_records",
                return_value=([], {"recordCount": 0, "reportedTotal": 0}),
            ),
            patch.object(
                main.db,
                "replace_vulnerability_passport_trends",
                return_value={"saved": 0, "skipped": 0},
            ) as replace,
        ):
            result = main.sync_trending_vulnerability_passports(
                client=client,
                token="token",
                utc_offset="+05:00",
                batch_size=5000,
                reconcile_links=False,
            )

        self.assertEqual(result["total"], 0)
        replace.assert_called_once_with(
            [],
            source_pdql=TRENDING_VULNERABILITY_PDQL,
            pdql_token="trend-token",
            reconcile_links=False,
        )

    def test_query_returns_before_background_details_run(self):
        client = SimpleNamespace(
            auth=SimpleNamespace(),
            create_pdql_token=lambda *_args, **_kwargs: "pdql-token",
        )
        records = [
            {"@VulnerPassport": {"internalId": f"passport-{index}", "name": f"Passport {index}"}}
            for index in range(100)
        ]
        summaries = [
            {"internal_id": f"passport-{index}", "name": f"Passport {index}", "has_detail": False}
            for index in range(50)
        ]
        background_tasks = BackgroundTasks()
        with (
            patch.object(main, "require_mpvm", return_value=(client, "token")),
            patch.object(main, "fetch_asset_grid_records", return_value=(records, {"recordCount": 100})),
            patch.object(main.db, "get_active_vulnerability_passport_detail_job", return_value=None),
            patch.object(main.db, "upsert_vulnerability_passports", return_value={"saved": 100, "skipped": 0}),
            patch.object(
                main,
                "sync_trending_vulnerability_passports",
                return_value={
                    "status": "completed",
                    "total": 2,
                    "db": {"saved": 2},
                },
            ) as trend_sync,
            patch.object(
                main.db,
                "vulnerability_passport_detail_refresh_candidates",
                return_value={
                    "requested": [f"passport-{index}" for index in range(100)],
                    "eligible": [f"passport-{index}" for index in range(75)],
                    "skipped_fresh": [f"passport-{index}" for index in range(75, 100)],
                },
            ),
            patch.object(
                main.db,
                "create_vulnerability_passport_detail_job",
                return_value={
                    "job_id": "job-1",
                    "status": "queued",
                    "eligible_count": 75,
                    "skipped_fresh_count": 25,
                },
            ),
            patch.object(
                main.db,
                "list_vulnerability_passports",
                return_value={"rows": summaries, "total": 100, "limit": 50, "offset": 0},
            ),
        ):
            response = main.query_vulnerability_passports(
                main.VulnerabilityPassportQueryRequest(),
                background_tasks,
            )

        self.assertEqual(response["total"], 100)
        self.assertEqual(len(response["records"]), 50)
        self.assertEqual(response["detail_job"]["status"], "queued")
        self.assertEqual(response["trend_sync"]["total"], 2)
        trend_sync.assert_called_once()
        self.assertEqual(len(background_tasks.tasks), 1)
        self.assertNotIn("raw_detail", response["records"][0])

    def test_query_rejects_a_second_active_detail_job(self):
        with patch.object(
            main.db,
            "get_active_vulnerability_passport_detail_job",
            return_value={"job_id": "existing", "status": "running"},
        ):
            with self.assertRaises(HTTPException) as raised:
                main.query_vulnerability_passports(
                    main.VulnerabilityPassportQueryRequest(),
                    BackgroundTasks(),
                )
        self.assertEqual(raised.exception.status_code, 409)


class DatabaseInitializationTests(unittest.TestCase):
    def test_init_db_runs_schema_initialization_once(self):
        original_initialized = db._DB_INITIALIZED
        calls = []
        try:
            db._DB_INITIALIZED = False
            with patch.object(db, "_initialize_schema", side_effect=lambda: calls.append(True)):
                db.init_db()
                db.init_db()
            self.assertEqual(calls, [True])
        finally:
            db._DB_INITIALIZED = original_initialized

    def test_detail_refresh_candidates_respect_24_hour_ttl(self):
        now = datetime.now(timezone.utc)
        rows = [
            {"internal_id": "fresh", "detail_updated_at": (now - timedelta(hours=1)).isoformat(), "has_detail": True},
            {"internal_id": "stale", "detail_updated_at": (now - timedelta(hours=25)).isoformat(), "has_detail": True},
            {"internal_id": "missing", "detail_updated_at": None, "has_detail": False},
        ]
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False
        connection.execute.return_value.fetchall.return_value = rows
        with patch.object(db, "init_db"), patch.object(db, "connect", return_value=connection):
            result = db.vulnerability_passport_detail_refresh_candidates(
                ["fresh", "stale", "missing"],
                ttl_hours=24,
            )

        self.assertEqual(result["skipped_fresh"], ["fresh"])
        self.assertEqual(result["eligible"], ["stale", "missing"])


if __name__ == "__main__":
    unittest.main()
