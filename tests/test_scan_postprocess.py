from __future__ import annotations

import threading
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import BackgroundTasks
from fastapi.testclient import TestClient

from app import main
from app import mpvm_client


class FakeSession:
    def close(self) -> None:
        pass


class PagingClient(mpvm_client.MpVmClient):
    def __init__(self) -> None:
        self.auth = SimpleNamespace()
        self.session = FakeSession()
        self.offsets: list[int] = []

    def get_run_jobs(self, _token, _run_id, *, offset=0, limit=1000, **_kwargs):
        self.offsets.append(offset)
        total = 2005
        return [{"id": str(index)} for index in range(offset, min(offset + limit, total))]


class ScanPostprocessClientTests(unittest.TestCase):
    def test_run_jobs_are_fetched_with_pagination(self):
        client = PagingClient()
        jobs = client.get_all_run_jobs("token", "run", batch_size=1000)

        self.assertEqual(len(jobs), 2005)
        self.assertEqual(client.offsets, [0, 1000, 2000])

    def test_main_job_becomes_successful_when_error_status_is_success(self):
        client = PagingClient()
        client.get_all_run_jobs = MagicMock(return_value=[
            {"id": "ok", "status": "assigned", "errorStatus": "success", "runMode": "default", "targets": ["10.0.0.1"]},
            {"id": "failed", "status": "finished", "errorStatus": "failed", "runMode": "default", "targets": ["10.0.0.2"]},
            {"id": "running", "status": "assigned", "errorStatus": None, "runMode": "default", "targets": ["10.0.0.3"]},
            {"id": "precheck", "status": "assigned", "errorStatus": "success", "runMode": "connectionCheck", "targets": ["10.0.0.4"]},
            {"id": "host-discovery", "status": "assigned", "errorStatus": "success", "runMode": "default", "profile": {"name": "HostDiscovery"}, "targets": ["10.0.0.5"]},
        ])

        jobs, successful = client.split_successful_run_jobs("token", "run")

        self.assertEqual(len(jobs), 5)
        self.assertEqual([job["id"] for job in successful], ["ok"])
        self.assertEqual(main.successful_scan_target_jobs(successful), {"10.0.0.1": "ok"})
        client.get_all_run_jobs.assert_called_once_with(
            "token",
            "run",
            target_pattern="",
            orderby="startedAt desc",
            batch_size=100,
        )

    def test_resolution_pdql_supports_ip_subnet_and_fqdn(self):
        self.assertIn("contains 10.0.0.1", mpvm_client.build_asset_resolution_pdql("10.0.0.1"))
        self.assertIn("Item in 10.0.0.0/24", mpvm_client.build_asset_resolution_pdql("10.0.0.7/24"))
        fqdn = mpvm_client.build_asset_resolution_pdql("host.example.org")
        self.assertIn("Host.Fqdn = 'host.example.org'", fqdn)


class ScanAssetResolutionTests(unittest.TestCase):
    def test_old_asset_in_successful_subnet_is_rejected(self):
        started = datetime.now(timezone.utc).replace(microsecond=0)
        old = {
            "IpAddress": "10.20.30.5",
            "UpdateTime": (started - timedelta(minutes=5)).isoformat(),
            "CreationTime": (started - timedelta(days=2)).isoformat(),
        }
        fresh = {**old, "UpdateTime": (started + timedelta(seconds=1)).isoformat()}

        self.assertTrue(main.scanned_asset_record_matches(old, "10.20.30.0/24"))
        self.assertFalse(main.scanned_asset_record_is_current(old, started.isoformat()))
        self.assertTrue(main.scanned_asset_record_is_current(fresh, started.isoformat()))

    def test_fqdn_match_is_exact_and_case_insensitive(self):
        record = {"Fqdn": "HOST.Example.Org."}
        self.assertTrue(main.scanned_asset_record_matches(record, "host.example.org"))
        self.assertFalse(main.scanned_asset_record_matches(record, "other.example.org"))

    def test_exact_ip_from_successful_job_does_not_require_update_time(self):
        record = {"AssetId": "11111111-1111-1111-1111-111111111111", "IpAddress": "10.0.0.1"}
        client = MagicMock()
        with patch.object(main, "query_scanned_asset_records", return_value=[record]):
            assets, error = main.resolve_scanned_target_once(
                client=client,
                token="token",
                target="10.0.0.1",
                mp_job_id="job-1",
                run_started_at="2026-01-01T00:00:00+00:00",
            )

        self.assertEqual(error, "")
        self.assertEqual(assets[0]["asset_id"], "11111111-1111-1111-1111-111111111111")


class ScanAssetProcessingOrderTests(unittest.TestCase):
    def test_card_is_saved_before_remote_removal_and_local_delete_is_unused(self):
        events: list[str] = []

        class RemovalClient:
            def __init__(self, _auth) -> None:
                self.session = FakeSession()

            def remove_assets(self, _token, asset_ids):
                events.append(f"remove:{asset_ids[0]}")
                return "operation-1"

            def wait_for_asset_removal(self, *_args, **_kwargs):
                events.append("removed")
                return True, "done", {"status": "completed"}

        item = {
            "id": 1,
            "postprocess_run_id": "post-1",
            "asset_id": "asset-1",
            "removal_operation_id": None,
        }
        with (
            patch.object(main, "MpVmClient", RemovalClient),
            patch.object(main, "build_scanned_asset_card", side_effect=lambda **_kwargs: events.append("card_saved") or "build-1"),
            patch.object(main.db, "update_scan_postprocess_item", return_value=item),
            patch.object(main.db, "delete_asset_card") as local_delete,
        ):
            main.process_scanned_asset_item(item=item, auth=SimpleNamespace(), token="token")

        self.assertEqual(events, ["card_saved", "remove:asset-1", "removed"])
        local_delete.assert_not_called()

    def test_build_failure_never_starts_remote_removal(self):
        class RemovalClient:
            def __init__(self, _auth) -> None:
                self.session = FakeSession()
                self.remove_assets = MagicMock()

        client = RemovalClient(SimpleNamespace())
        item = {"id": 1, "postprocess_run_id": "post-1", "asset_id": "asset-1", "removal_operation_id": None}
        updates: list[dict] = []
        with (
            patch.object(main, "MpVmClient", return_value=client),
            patch.object(main, "build_scanned_asset_card", side_effect=RuntimeError("build failed")),
            patch.object(main.db, "update_scan_postprocess_item", side_effect=lambda _id, **kwargs: updates.append(kwargs) or item),
        ):
            main.process_scanned_asset_item(item=item, auth=SimpleNamespace(), token="token")

        client.remove_assets.assert_not_called()
        self.assertEqual(updates[-1]["status"], "build_failed")

    def test_existing_removal_operation_is_polled_without_duplicate_delete(self):
        class RemovalClient:
            def __init__(self, _auth) -> None:
                self.session = FakeSession()
                self.remove_assets = MagicMock()

            def wait_for_asset_removal(self, _token, operation_id, **_kwargs):
                self.polled = operation_id
                return True, "done", {"status": "completed"}

        client = RemovalClient(SimpleNamespace())
        item = {
            "id": 1,
            "postprocess_run_id": "post-1",
            "asset_id": "asset-1",
            "removal_operation_id": "operation-existing",
        }
        updates: list[dict] = []
        with (
            patch.object(main, "MpVmClient", return_value=client),
            patch.object(main, "build_scanned_asset_card") as build,
            patch.object(main.db, "update_scan_postprocess_item", side_effect=lambda _id, **kwargs: updates.append(kwargs) or item),
        ):
            main.process_scanned_asset_item(item=item, auth=SimpleNamespace(), token="token")

        build.assert_not_called()
        client.remove_assets.assert_not_called()
        self.assertEqual(client.polled, "operation-existing")
        self.assertEqual(updates[-1]["status"], "completed")


class StartScannerTaskApiTests(unittest.TestCase):
    def test_start_returns_postprocess_run_and_schedules_background_monitor(self):
        background = BackgroundTasks()
        client = SimpleNamespace(auth=SimpleNamespace(api_url="https://fixture"))
        postprocess = {"run_id": "post-1", "status": "monitoring", "stage": "waiting_for_run"}
        with (
            patch.object(main, "require_mpvm", return_value=(client, "token")),
            patch.object(main, "start_scanner_task_impl", return_value={
                "id": "task-1",
                "status": "started",
                "started_from": "2026-01-01T00:00:00+00:00",
            }),
            patch.object(main.uuid, "uuid4", return_value="post-1"),
            patch.object(main.db, "create_scan_postprocess_run", return_value=postprocess),
        ):
            result = main.start_scanner_task("task-1", background, main.StartScannerTaskRequest())

        self.assertEqual(result["postprocess_run_id"], "post-1")
        self.assertEqual(result["postprocess"]["status"], "monitoring")
        self.assertEqual(len(background.tasks), 1)

    def test_http_start_is_accepted_and_background_schedule_runs(self):
        client = SimpleNamespace(auth=SimpleNamespace(api_url="https://fixture"))
        postprocess = {"run_id": "post-http", "status": "monitoring", "stage": "waiting_for_run"}
        with (
            patch.object(main, "require_mpvm", return_value=(client, "token")),
            patch.object(main, "start_scanner_task_impl", return_value={
                "id": "task-http",
                "status": "started",
                "started_from": "2026-01-01T00:00:00+00:00",
            }),
            patch.object(main.uuid, "uuid4", return_value="post-http"),
            patch.object(main.db, "create_scan_postprocess_run", return_value=postprocess),
            patch.object(main, "schedule_scan_postprocess") as schedule,
        ):
            response = TestClient(main.app).post(
                "/api/scanner-tasks/task-http/start",
                json={"wait_for_finish": True, "task_poll_seconds": 1},
            )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["postprocess_run_id"], "post-http")
        schedule.assert_called_once_with("post-http", client.auth, "token")

    def test_http_background_task_runs_the_full_orchestrator(self):
        auth = SimpleNamespace(api_url="https://fixture")
        endpoint_client = SimpleNamespace(auth=auth)
        postprocess = {"run_id": "post-full", "status": "monitoring", "stage": "waiting_for_run"}
        claimed = {
            **postprocess,
            "mp_task_id": "task-full",
            "started_from": "2026-01-01T00:00:00+00:00",
            "options": {"task_timeout_minutes": 1, "task_poll_seconds": 1},
        }
        item = {
            "id": 1,
            "postprocess_run_id": "post-full",
            "item_key": "asset:asset-1",
            "asset_id": "asset-1",
            "status": "queued",
        }

        class OrchestratorClient:
            def __init__(self, _auth) -> None:
                self.session = FakeSession()

        with (
            patch.object(main, "require_mpvm", return_value=(endpoint_client, "token")),
            patch.object(main, "start_scanner_task_impl", return_value={
                "id": "task-full",
                "status": "started",
                "started_from": "2026-01-01T00:00:00+00:00",
            }),
            patch.object(main.uuid, "uuid4", return_value="post-full"),
            patch.object(main.db, "create_scan_postprocess_run", return_value=postprocess),
            patch.object(main, "schedule_scan_postprocess", side_effect=lambda run_id, run_auth, run_token: main.run_scan_postprocess(run_id=run_id, auth=run_auth, token=run_token)),
            patch.object(main, "MpVmClient", OrchestratorClient),
            patch.object(main.db, "claim_scan_postprocess_run", return_value=claimed),
            patch.object(main, "monitor_successful_scan_jobs", return_value={"successful_job_count": 1, "total_job_count": 1, "asset_count": 1}),
            patch.object(main.db, "refresh_scan_postprocess_counts", return_value={"completed_count": 1, "failed_count": 0}),
            patch.object(main.db, "update_scan_postprocess_run"),
            patch.object(main.db, "finish_scan_postprocess_run") as finish_run,
            patch.object(main.db, "update_scan_task_status"),
        ):
            response = TestClient(main.app).post("/api/scanner-tasks/task-full/start", json={})

        self.assertEqual(response.status_code, 202)
        self.assertEqual(finish_run.call_args.kwargs["status"], "completed")


class ScanJobLiveMonitoringTests(unittest.TestCase):
    def test_success_error_status_schedules_card_before_run_finishes(self):
        running = {"id": "run-1", "status": "running", "startedAt": "2026-01-01T00:00:00+00:00"}
        finished = {**running, "status": "finished", "finishedAt": "2026-01-01T00:01:00+00:00"}
        job = {
            "id": "job-1",
            "status": "assigned",
            "errorStatus": "success",
            "runMode": "default",
            "targets": ["10.0.0.1"],
        }
        client = MagicMock()
        client.get_task_runs.side_effect = [[running], [finished]]
        client.split_successful_run_jobs.return_value = ([job], [job])
        item = {
            "id": 1,
            "postprocess_run_id": "post-1",
            "item_key": "asset:asset-1",
            "asset_id": "asset-1",
            "status": "queued",
        }
        with (
            patch.object(main.db, "list_scan_postprocess_items", return_value=[]),
            patch.object(main.db, "upsert_scan_postprocess_item", return_value=item),
            patch.object(main.db, "update_scan_postprocess_run") as update_run,
            patch.object(main, "resolve_scanned_target_once", return_value=([{
                "asset_id": "asset-1",
                "target": "10.0.0.1",
                "mp_job_id": "job-1",
                "display_name": "Host 1",
            }], "")),
            patch.object(main, "process_scanned_asset_item") as process_item,
            patch.object(main.db, "refresh_scan_postprocess_counts"),
            patch.object(main.time, "sleep"),
        ):
            result = main.monitor_successful_scan_jobs(
                client=client,
                auth=SimpleNamespace(),
                token="token",
                task_id="task-1",
                started_from="2026-01-01T00:00:00+00:00",
                timeout_seconds=60,
                poll_seconds=1,
                postprocess_run_id="post-1",
                require_clean_jobs=False,
            )

        self.assertEqual(result["successful_job_count"], 1)
        process_item.assert_called_once()
        first_update = update_run.call_args_list[0].kwargs
        self.assertEqual(first_update["successful_job_count"], 1)


if __name__ == "__main__":
    unittest.main()
