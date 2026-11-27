from __future__ import annotations

import threading
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

from app import main


def _built_card() -> dict:
    return {
        "asset_id": "asset-1",
        "stats": {"nodes": 1, "collections": 1, "warnings": []},
        "vulnerabilities": {"stats": {"findings": 2}},
    }


class FakeSession:
    def close(self) -> None:
        pass


class SnapshotSafetyTests(unittest.TestCase):
    def test_best_effort_capture_logs_and_does_not_propagate_failure(self):
        service = main.CONTAINER.services.vulnerabilities
        with (
            patch.object(service, "capture_snapshot", side_effect=RuntimeError("database unavailable")) as capture,
            patch.object(main, "log_exception") as log_exception,
        ):
            result = main.capture_vulnerability_snapshot("asset_card_build", "job-1")

        self.assertIsNone(result)
        capture.assert_called_once_with(trigger_kind="asset_card_build", trigger_id="job-1")
        log_exception.assert_called_once_with(
            "vulnerabilities",
            "snapshot.capture.failed",
            trigger_kind="asset_card_build",
            trigger_id="job-1",
        )


class AssetCardSnapshotTriggerTests(unittest.TestCase):
    def _run_build(self, *, job_id: str, request: dict, capture: MagicMock) -> None:
        with (
            patch.object(main.db, "start_asset_card_build_job", return_value={"status": "running"}),
            patch.object(main.db, "update_asset_card_build_job"),
            patch.object(main.db, "upsert_asset_card", return_value={"asset_id": "asset-1"}),
            patch.object(main.db, "finish_asset_card_build_job"),
            patch.object(main, "build_asset_card", return_value=_built_card()),
            patch.object(main, "capture_vulnerability_snapshot", capture),
        ):
            main.run_asset_card_build_job(
                job_id=job_id,
                auth=SimpleNamespace(api_url="https://fixture"),
                token="token",
                request=request,
                cancel_event=threading.Event(),
            )

    def test_standalone_async_build_captures_one_snapshot(self):
        capture = MagicMock()

        self._run_build(job_id="job-standalone", request={"asset_id": "asset-1"}, capture=capture)

        capture.assert_called_once_with("asset_card_build", "job-standalone")

    def test_scan_child_async_build_does_not_capture_snapshot(self):
        capture = MagicMock()

        self._run_build(
            job_id="job-child",
            request={"asset_id": "asset-1", "parent_operation_id": "postprocess-1"},
            capture=capture,
        )

        capture.assert_not_called()

    def test_synchronous_update_and_delete_capture_distinct_triggers(self):
        capture = MagicMock()
        client = SimpleNamespace()
        with (
            patch.object(main.db, "asset_card_exists", return_value=True),
            patch.object(main, "require_mpvm", return_value=(client, "token")),
            patch.object(main, "build_asset_card", return_value=_built_card()),
            patch.object(main.db, "upsert_asset_card", return_value={"asset_id": "asset-1"}),
            patch.object(main.db, "delete_asset_card", return_value=True),
            patch.object(main, "current_trace_id", side_effect=["trace-update", "trace-delete"]),
            patch.object(main, "capture_vulnerability_snapshot", capture),
        ):
            updated = main.update_local_asset_card("asset-1", main.AssetCardUpdateRequest())
            deleted = main.delete_local_asset_card("asset-1")

        self.assertTrue(updated["updated"])
        self.assertTrue(deleted["deleted"])
        self.assertEqual(
            capture.call_args_list,
            [
                call("asset_card_update", "trace-update"),
                call("asset_card_delete", "trace-delete"),
            ],
        )


class ScanPostprocessSnapshotTriggerTests(unittest.TestCase):
    def test_completed_parent_run_captures_exactly_one_snapshot(self):
        claimed = {
            "run_id": "postprocess-1",
            "mp_task_id": "task-1",
            "started_from": "2026-07-12T00:00:00+00:00",
            "options": {"task_timeout_minutes": 1, "task_poll_seconds": 1},
        }

        class ScanClient:
            def __init__(self, _auth) -> None:
                self.session = FakeSession()

        with (
            patch.object(main, "MpVmClient", ScanClient),
            patch.object(main.db, "claim_scan_postprocess_run", return_value=claimed),
            patch.object(
                main,
                "monitor_successful_scan_jobs",
                return_value={"successful_job_count": 2, "total_job_count": 2},
            ),
            patch.object(
                main.db,
                "refresh_scan_postprocess_counts",
                return_value={"completed_count": 2, "failed_count": 0},
            ),
            patch.object(main, "finalize_asset_card_refresh", return_value=None),
            patch.object(main.db, "update_scan_task_status"),
            patch.object(main.db, "finish_scan_postprocess_run"),
            patch.object(main, "capture_vulnerability_snapshot") as capture,
        ):
            main.run_scan_postprocess(
                run_id="postprocess-1",
                auth=SimpleNamespace(),
                token="token",
            )

        capture.assert_called_once_with("scan_postprocess", "postprocess-1")


if __name__ == "__main__":
    unittest.main()
