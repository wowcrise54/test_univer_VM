from __future__ import annotations

import threading
import unittest
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import BackgroundTasks
from fastapi.testclient import TestClient

from app import main, mpvm_client


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

        self.assertEqual([job["id"] for job in jobs], ["ok", "failed", "running", "precheck"])
        self.assertEqual([job["id"] for job in successful], ["ok"])
        self.assertEqual(main.successful_scan_target_jobs(successful), {"10.0.0.1": "ok"})
        client.get_all_run_jobs.assert_called_once_with(
            "token",
            "run",
            target_pattern="",
            orderby="startedAt desc",
            batch_size=100,
        )

    def test_empty_accepted_asset_removal_response_is_still_processing(self):
        client = mpvm_client.MpVmClient(mpvm_client.AuthConfig(
            api_url="https://fixture",
            token_url="https://fixture/token",
            access_token="token",
        ))
        response = MagicMock(status_code=202, content=b"", ok=True)
        client.session.get = MagicMock(return_value=response)

        operation = client.get_asset_removal_operation("token", "operation-1")

        self.assertEqual(operation, {"status": "processing", "httpStatus": 202})
        response.json.assert_not_called()
        client.session.close()

    def test_delete_scanner_task_treats_not_found_as_already_deleted(self):
        client = mpvm_client.MpVmClient(mpvm_client.AuthConfig(
            api_url="https://fixture",
            token_url="https://fixture/token",
            access_token="token",
        ))
        response = MagicMock(status_code=404, content=b"", ok=False)
        client.session.delete = MagicMock(return_value=response)

        result = client.delete_scanner_task("token", "task-gone")

        self.assertEqual(result, {"id": "task-gone", "mode": "delete_v3", "alreadyDeleted": True})
        client.session.close()

    def test_asset_removal_wait_continues_after_empty_accepted_response(self):
        client = mpvm_client.MpVmClient(mpvm_client.AuthConfig(
            api_url="https://fixture",
            token_url="https://fixture/token",
            access_token="token",
        ))
        client.get_asset_removal_operation = MagicMock(side_effect=[
            {"status": "processing", "httpStatus": 202},
            {"status": "completed", "totalCount": 1, "succeedCount": 1, "failedCount": 0},
        ])

        with patch.object(mpvm_client.time, "sleep"):
            ok, message, operation = client.wait_for_asset_removal(
                "token",
                "operation-1",
                timeout_seconds=1,
                poll_seconds=0,
            )

        self.assertTrue(ok)
        self.assertEqual(message, "total=1, succeed=1, failed=0")
        self.assertEqual(operation["status"], "completed")
        self.assertEqual(client.get_asset_removal_operation.call_count, 2)

    def test_asset_removal_wait_stops_when_parent_operation_is_cancelled(self):
        client = mpvm_client.MpVmClient(mpvm_client.AuthConfig(
            api_url="https://fixture",
            token_url="https://fixture/token",
            access_token="token",
        ))
        client.get_asset_removal_operation = MagicMock()
        cancel_event = threading.Event()
        cancel_event.set()

        ok, message, operation = client.wait_for_asset_removal(
            "token",
            "operation-1",
            timeout_seconds=60,
            cancel_event=cancel_event,
        )

        self.assertFalse(ok)
        self.assertEqual(message, "cancelled by operator")
        self.assertIsNone(operation)
        client.get_asset_removal_operation.assert_not_called()
        client.session.close()
        client.session.close()

    def test_resolution_pdql_supports_ip_subnet_and_fqdn(self):
        self.assertIn("contains 10.0.0.1", mpvm_client.build_asset_resolution_pdql("10.0.0.1"))
        self.assertIn("Item in 10.0.0.0/24", mpvm_client.build_asset_resolution_pdql("10.0.0.7/24"))
        fqdn = mpvm_client.build_asset_resolution_pdql("host.example.org")
        self.assertIn("Host.Fqdn = 'host.example.org'", fqdn)


class ScanAssetResolutionTests(unittest.TestCase):
    def test_old_asset_in_successful_subnet_is_rejected(self):
        started = datetime.now(UTC).replace(microsecond=0)
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

    def test_host_object_from_pdql_is_normalized_to_text_display_name(self):
        record = {
            "AssetId": "11111111-1111-1111-1111-111111111111",
            "HostName": {
                "objectId": "11111111-1111-1111-1111-111111111111",
                "displayName": "Windows host 01",
                "type": "host",
            },
            "IpAddress": "10.0.0.1",
        }

        asset = main.normalize_scanned_asset_record(record, target="10.0.0.1", mp_job_id="job-1")

        self.assertEqual(asset["display_name"], "Windows host 01")
        self.assertIsInstance(asset["display_name"], str)

    def test_structured_queue_fields_are_serialized_before_psycopg(self):
        stored = {
            "id": 1,
            "postprocess_run_id": "post-1",
            "item_key": "asset:asset-1",
            "status": "queued",
            "stage": "queued",
        }
        result = MagicMock()
        result.fetchone.return_value = stored
        connection = MagicMock()
        connection.execute.return_value = result
        connect = MagicMock()
        connect.return_value.__enter__.return_value = connection

        with patch.object(main.db, "connect", connect):
            item = main.db.upsert_scan_postprocess_item(
                "post-1",
                item_key="asset:asset-1",
                mp_job_id={"id": "job-1"},
                target={"address": "10.0.0.1"},
                asset_id={"id": "asset-1"},
                display_name={"displayName": "Host 1"},
                status="queued",
                stage="queued",
            )

        params = connection.execute.call_args.args[1]
        self.assertTrue(all(not isinstance(value, dict) for value in params))
        self.assertIn('"displayName": "Host 1"', params[5])
        self.assertEqual(item["status"], "queued")


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
            patch.object(main.app_auth, "get_session_user", return_value={"id": 1, "role": "operator"}),
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
            patch.object(main, "capture_vulnerability_snapshot") as capture_snapshot,
            patch.object(main.app_auth, "get_session_user", return_value={"id": 1, "role": "operator"}),
        ):
            response = TestClient(main.app).post("/api/scanner-tasks/task-full/start", json={})

        self.assertEqual(response.status_code, 202)
        self.assertEqual(finish_run.call_args.kwargs["status"], "completed")
        capture_snapshot.assert_called_once_with("scan_postprocess", "post-full")


class AssetCardRefreshScanTests(unittest.TestCase):
    def test_cancelled_child_operation_cancels_automation_step_without_retry(self):
        with patch.object(main.db, "get_operation", return_value={"status": "cancelled"}):
            with self.assertRaises(main.AutomationStepCancelled):
                main.wait_for_automation_operation("refresh-run-1", 1)

    def test_automation_asset_card_step_uses_refresh_scan_pipeline(self):
        registered: list[str] = []
        with (
            patch.object(main, "refresh_asset_card_by_scan", return_value={
                "postprocess_run_id": "refresh-run-1",
                "operation_id": "refresh-run-1",
            }) as refresh_scan,
            patch.object(main, "run_background_tasks"),
            patch.object(main, "wait_for_automation_operation", return_value={"status": "completed"}) as wait_operation,
            patch.object(main, "create_asset_card_build_job") as direct_build,
        ):
            result = main.execute_automation_step(
                "asset_card_build",
                {
                    "asset_id": "asset-old",
                    "template_task_id": "template-task-1",
                    "start_options": {"task_timeout_minutes": 30},
                },
                {
                    "_register_child_operation": registered.append,
                    "_is_cancel_requested": lambda: False,
                },
                "automation-run-1",
                0,
            )

        self.assertEqual(result["operation_id"], "refresh-run-1")
        self.assertEqual(registered, ["refresh-run-1"])
        refresh_scan.assert_called_once()
        payload = refresh_scan.call_args.args[1]
        self.assertEqual(payload.template_task_id, "template-task-1")
        self.assertEqual(payload.start_options.task_timeout_minutes, 30)
        wait_operation.assert_called_once()
        direct_build.assert_not_called()

    def test_automation_refreshes_all_stale_cards_sequentially(self):
        coverage = main.CONTAINER.services.coverage
        page = {
            "rows": [
                {"asset_id": "asset-stale-1", "stale": True},
                {"asset_id": "asset-stale-2", "stale": True},
            ],
            "total": 2,
        }
        completed: list[str] = []

        def refresh_one(**kwargs):
            completed.append(kwargs["asset_id"])
            return {"operation_id": f"operation-{kwargs['asset_id']}"}

        with (
            patch.object(coverage, "list_assets", return_value=page) as list_assets,
            patch.object(main, "refresh_one_asset_card_for_automation", side_effect=refresh_one) as refresh,
        ):
            result = main.execute_automation_step(
                "asset_card_build",
                {"selection": "stale", "wait": True},
                {"_is_cancel_requested": lambda: False},
                "automation-run-1",
                0,
            )

        self.assertEqual(completed, ["asset-stale-1", "asset-stale-2"])
        self.assertEqual(result["selected_count"], 2)
        self.assertEqual(result["completed_count"], 2)
        self.assertEqual(result["failed_count"], 0)
        list_assets.assert_called_once_with(q=None, issue="stale", limit=500, offset=0)
        self.assertIn(":stale:0:asset-stale-1", refresh.call_args_list[0].kwargs["idempotency_key"])
        self.assertIn(":stale:1:asset-stale-2", refresh.call_args_list[1].kwargs["idempotency_key"])

    def test_stale_automation_completes_cleanly_when_nothing_is_outdated(self):
        coverage = main.CONTAINER.services.coverage
        with patch.object(coverage, "list_assets", return_value={"rows": [], "total": 0}):
            result = main.refresh_stale_asset_cards_for_automation(
                config={"selection": "stale"},
                register_child=None,
                cancel_check=None,
                run_id="automation-run-1",
                step_index=0,
            )

        self.assertEqual(result["selected_count"], 0)
        self.assertEqual(result["completed_count"], 0)

    def test_refresh_task_reuses_scan_settings_and_targets_only_card_ip(self):
        template = {
            "name": "Regular audit",
            "description": "template",
            "scope": "scope-1",
            "profile": "profile-1",
            "agents": {"agentIds": ["agent-1"]},
            "overrides": {"credential": "preserved"},
            "include": {"assets": ["old"], "targets": ["10.0.0.0/24"], "assetsGroups": ["group"]},
            "exclude": {"assets": ["old"], "targets": ["10.0.0.8"], "assetsGroups": ["group"]},
            "triggerParameters": {"isEnabled": True, "type": "Daily"},
        }

        result = main.build_asset_refresh_task_payload(
            template,
            asset_id="asset-old",
            target_ip="10.0.0.7",
            display_name="host-7",
        )

        self.assertEqual(result["scope"], "scope-1")
        self.assertEqual(result["profile"], "profile-1")
        self.assertEqual(result["agents"], {"agentIds": ["agent-1"]})
        self.assertEqual(result["overrides"], {"credential": "preserved"})
        self.assertEqual(result["include"], {"assets": [], "targets": ["10.0.0.7"], "assetsGroups": []})
        self.assertEqual(result["exclude"], {"assets": [], "targets": [], "assetsGroups": []})
        self.assertFalse(result["triggerParameters"]["isEnabled"])
        self.assertEqual(template["include"]["targets"], ["10.0.0.0/24"])

    def test_refresh_endpoint_creates_and_starts_normal_scanner_pipeline(self):
        background = BackgroundTasks()
        client = MagicMock(auth=SimpleNamespace(api_url="https://fixture"))
        client.create_scanner_task.return_value = "refresh-task-1"
        template = {
            "mp_task_id": "template-task-1",
            "payload": {
                "name": "Regular audit",
                "scope": "scope-1",
                "profile": "profile-1",
                "include": {"targets": ["10.0.0.0/24"]},
                "exclude": {"targets": []},
            },
        }
        postprocess = {
            "run_id": "refresh-run-1",
            "mp_task_id": "refresh-task-1",
            "status": "monitoring",
            "stage": "waiting_for_run",
        }
        with (
            patch.object(main.db, "get_operation_by_idempotency_key", return_value=None),
            patch.object(main.db, "get_asset_card", return_value={"asset_id": "asset-old", "ip_address": "10.0.0.7", "display_name": "host-7"}),
            patch.object(main.db, "get_active_asset_card_refresh", return_value=None),
            patch.object(main.db, "get_asset_card_refresh_template", return_value=template),
            patch.object(main, "require_mpvm", return_value=(client, "token")),
            patch.object(main.db, "record_scan_task") as record_task,
            patch.object(main, "start_scanner_task_impl", return_value={"id": "refresh-task-1", "status": "started", "started_from": "2026-01-01T00:00:00+00:00"}),
            patch.object(main.uuid, "uuid4", return_value="refresh-run-1"),
            patch.object(main.db, "create_scan_postprocess_run", return_value=postprocess) as create_run,
        ):
            result = main.refresh_asset_card_by_scan(
                "asset-old",
                main.AssetCardRefreshScanRequest(),
                background,
                "refresh-key-1",
            )

        self.assertEqual(result["task_id"], "refresh-task-1")
        self.assertEqual(result["target_ip"], "10.0.0.7")
        self.assertEqual(result["postprocess_run_id"], "refresh-run-1")
        created_payload = client.create_scanner_task.call_args.args[1]
        self.assertEqual(created_payload["include"]["targets"], ["10.0.0.7"])
        record_task.assert_called_once()
        self.assertEqual(create_run.call_args.kwargs["options"]["refresh_asset_id"], "asset-old")
        self.assertEqual(len(background.tasks), 1)

    def test_successful_refresh_replaces_old_card_only_after_new_card_exists(self):
        items = [{"status": "completed", "asset_id": "asset-new"}]
        with (
            patch.object(main.db, "list_scan_postprocess_items", return_value=items),
            patch.object(main.db, "asset_card_exists", return_value=True),
            patch.object(main.db, "delete_asset_card", return_value=True) as delete_card,
        ):
            result = main.finalize_asset_card_refresh("run-1", {"refresh_asset_id": "asset-old"})

        self.assertEqual(result, {"previous_asset_id": "asset-old", "asset_id": "asset-new"})
        delete_card.assert_called_once_with("asset-old")

    def test_failed_refresh_keeps_old_card(self):
        with (
            patch.object(main.db, "list_scan_postprocess_items", return_value=[{"status": "build_failed", "asset_id": "asset-new"}]),
            patch.object(main.db, "asset_card_exists", return_value=False),
            patch.object(main.db, "delete_asset_card") as delete_card,
        ):
            result = main.finalize_asset_card_refresh("run-1", {"refresh_asset_id": "asset-old"})

        self.assertIsNone(result)
        delete_card.assert_not_called()

    def test_refresh_task_is_deleted_remotely_then_locally(self):
        client = MagicMock()
        client.delete_scanner_task.return_value = {"id": "refresh-task-1", "mode": "delete_v3"}
        with (
            patch.object(main.db, "delete_scan_task") as delete_local,
            patch.object(main, "update_refresh_task_cleanup_message") as update_message,
        ):
            deleted = main.cleanup_auto_created_refresh_task(
                client=client,
                token="token",
                run_id="refresh-run-1",
                task_id="refresh-task-1",
            )

        self.assertTrue(deleted)
        client.delete_scanner_task.assert_called_once_with("token", "refresh-task-1", mode="delete_v3")
        delete_local.assert_called_once_with("refresh-task-1")
        update_message.assert_called_once()

    def test_refresh_task_is_kept_locally_when_remote_deletion_fails(self):
        client = MagicMock()
        client.delete_scanner_task.side_effect = mpvm_client.MpVmApiError("temporary failure")
        with (
            patch.object(main.db, "delete_scan_task") as delete_local,
            patch.object(main, "update_refresh_task_cleanup_message") as update_message,
        ):
            deleted = main.cleanup_auto_created_refresh_task(
                client=client,
                token="token",
                run_id="refresh-run-1",
                task_id="refresh-task-1",
            )

        self.assertFalse(deleted)
        delete_local.assert_not_called()
        update_message.assert_called_once()

    def test_refresh_task_cleanup_happens_after_card_actions_and_before_terminal_status(self):
        events: list[str] = []
        claimed = {
            "run_id": "refresh-run-1",
            "mp_task_id": "refresh-task-1",
            "started_from": "2026-01-01T00:00:00+00:00",
            "options": {
                "task_timeout_minutes": 1,
                "task_poll_seconds": 1,
                "refresh_asset_id": "asset-old",
                "auto_created_refresh_task": True,
            },
        }

        class RefreshClient:
            def __init__(self, _auth) -> None:
                self.session = FakeSession()

        with (
            patch.object(main, "MpVmClient", RefreshClient),
            patch.object(main.db, "claim_scan_postprocess_run", return_value=claimed),
            patch.object(main, "monitor_successful_scan_jobs", side_effect=lambda **_kwargs: events.append("card_actions") or {"successful_job_count": 1, "total_job_count": 1}),
            patch.object(main.db, "refresh_scan_postprocess_counts", return_value={"completed_count": 1, "failed_count": 0}),
            patch.object(main, "finalize_asset_card_refresh", return_value={"previous_asset_id": "asset-old", "asset_id": "asset-new"}),
            patch.object(main.db, "update_scan_task_status", side_effect=lambda *_args, **_kwargs: events.append("task_status")),
            patch.object(main, "cleanup_auto_created_refresh_task", side_effect=lambda **_kwargs: events.append("task_deleted") or True),
            patch.object(main.db, "finish_scan_postprocess_run", side_effect=lambda *_args, **_kwargs: events.append("terminal")),
            patch.object(main, "capture_vulnerability_snapshot", side_effect=lambda *_args, **_kwargs: events.append("snapshot")),
        ):
            main.run_scan_postprocess(run_id="refresh-run-1", auth=SimpleNamespace(), token="token")

        self.assertEqual(events, ["card_actions", "task_status", "task_deleted", "terminal", "snapshot"])

    def test_no_successful_jobs_finishes_with_errors_instead_of_failed(self):
        claimed = {
            "run_id": "post-1",
            "mp_task_id": "task-1",
            "started_from": "2026-01-01T00:00:00+00:00",
            "options": {"task_timeout_minutes": 1, "task_poll_seconds": 1},
        }

        class ScanClient:
            def __init__(self, _auth) -> None:
                self.session = FakeSession()

        with (
            patch.object(main, "MpVmClient", ScanClient),
            patch.object(main.db, "claim_scan_postprocess_run", return_value=claimed),
            patch.object(main, "monitor_successful_scan_jobs", return_value={"successful_job_count": 0, "total_job_count": 2}),
            patch.object(main.db, "update_scan_task_status") as update_task,
            patch.object(main.db, "finish_scan_postprocess_run") as finish,
        ):
            main.run_scan_postprocess(run_id="post-1", auth=SimpleNamespace(), token="token")

        self.assertEqual(update_task.call_args.args[1], "postprocess_completed_with_errors")
        self.assertEqual(finish.call_args.kwargs["status"], "completed_with_errors")

    def test_all_asset_errors_finish_with_errors_instead_of_failed(self):
        claimed = {
            "run_id": "post-1",
            "mp_task_id": "task-1",
            "started_from": "2026-01-01T00:00:00+00:00",
            "options": {"task_timeout_minutes": 1, "task_poll_seconds": 1},
        }

        class ScanClient:
            def __init__(self, _auth) -> None:
                self.session = FakeSession()

        with (
            patch.object(main, "MpVmClient", ScanClient),
            patch.object(main.db, "claim_scan_postprocess_run", return_value=claimed),
            patch.object(main, "monitor_successful_scan_jobs", return_value={"successful_job_count": 2, "total_job_count": 2}),
            patch.object(main.db, "refresh_scan_postprocess_counts", return_value={"completed_count": 0, "failed_count": 2}),
            patch.object(main.db, "update_scan_task_status") as update_task,
            patch.object(main.db, "finish_scan_postprocess_run") as finish,
        ):
            main.run_scan_postprocess(run_id="post-1", auth=SimpleNamespace(), token="token")

        self.assertEqual(update_task.call_args.args[1], "postprocess_completed_with_errors")
        self.assertEqual(finish.call_args.kwargs["status"], "completed_with_errors")


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
        with self.assertLogs("uvicorn.error", level="INFO") as captured_logs:
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
        self.assertEqual(result["total_job_count"], 1)
        process_item.assert_called_once()
        first_update = update_run.call_args_list[0].kwargs
        self.assertEqual(first_update["successful_job_count"], 1)
        self.assertNotIn("job-host-discovery", "\n".join(captured_logs.output))

    def test_asset_queue_database_failure_is_logged_and_retried(self):
        running = {"id": "run-1", "status": "running", "startedAt": "2026-01-01T00:00:00+00:00"}
        finished = {**running, "status": "finished", "finishedAt": "2026-01-01T00:01:00+00:00"}
        job = {
            "id": "job-1",
            "status": "finished",
            "errorStatus": "success",
            "runMode": "default",
            "targets": ["10.0.0.1"],
        }
        asset = {
            "asset_id": "asset-1",
            "target": "10.0.0.1",
            "mp_job_id": "job-1",
            "display_name": "Host 1",
        }
        item = {
            "id": 1,
            "postprocess_run_id": "post-1",
            "item_key": "asset:asset-1",
            "asset_id": "asset-1",
            "status": "queued",
        }
        client = MagicMock()
        client.get_task_runs.side_effect = [[running], [finished]]
        client.split_successful_run_jobs.return_value = ([job], [job])

        with self.assertLogs("uvicorn.error", level="INFO") as captured_logs:
            with (
                patch.object(main.db, "list_scan_postprocess_items", return_value=[]),
                patch.object(
                    main.db,
                    "upsert_scan_postprocess_item",
                    side_effect=[RuntimeError("database unavailable"), item],
                ) as upsert_item,
                patch.object(main.db, "update_scan_postprocess_run"),
                patch.object(main, "resolve_scanned_target_once", return_value=([asset], "")) as resolve_target,
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

        self.assertEqual(result["asset_count"], 1)
        self.assertEqual(upsert_item.call_count, 2)
        self.assertEqual(resolve_target.call_count, 2)
        process_item.assert_called_once()
        logs = "\n".join(captured_logs.output)
        self.assertIn("asset queue persistence failed", logs)
        self.assertIn("asset_queue_retry_pending", logs)
        self.assertIn("asset_queued", logs)


if __name__ == "__main__":
    unittest.main()
