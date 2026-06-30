from __future__ import annotations

import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import BackgroundTasks
from fastapi import HTTPException

from app import db
from app import main


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
