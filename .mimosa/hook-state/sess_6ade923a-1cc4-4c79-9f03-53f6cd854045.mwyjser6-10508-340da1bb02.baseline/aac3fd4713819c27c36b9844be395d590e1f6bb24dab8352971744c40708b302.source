"""Regression tests for precheck connection-check polling.

Incident 2026-09-02, task ``1e9e9459-d180-0001-0000-000000000006``:
the connection-check run stayed in-progress for the whole
``precheck_timeout_minutes`` window (both ``/start`` calls took ~606 s =
the full 10-minute poll), connection-check jobs with real results were
returned by MPVM every poll (response payloads grew 473 -> 64,183 bytes),
yet the precheck ended ``precheck_failed`` with ``successful_targets=[]``.

Two client-side defects made that possible (app/mpvm_client.py):

1. The timeout branch of ``wait_for_connection_check_targets`` discarded
   every target collected during the poll window and returned ``[]`` —
   so even partially successful runs failed the parent task.
2. ``is_finished`` treated a set ``finishedAt`` as terminal even when the
   status was explicitly in-progress, which lets MPVM report a run as
   finished while its jobs are still running (early-exit with no targets).
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from app.mpvm_client import (
    MpVmClient,
    extract_successful_connection_targets,
    is_finished,
    is_successful_connection_check_job,
)

GREEN_JOB = {
    "id": "job-1",
    "status": "finished",
    "errorStatus": "success",
    "runMode": "connectionCheck",
    "targets": ["10.0.0.4"],
    "connectionCheckResults": [{"status": "success", "errors": []}],
}


class IsFinishedTests(unittest.TestCase):
    def test_in_progress_run_with_finished_at_is_not_finished(self):
        # MPVM may carry finishedAt while the run is still in progress;
        # such a run must not be treated as terminal.
        run = {"id": "run-1", "status": "inProgress", "finishedAt": "2026-09-02T09:42:56Z"}
        self.assertFalse(is_finished(run))

    def test_running_status_with_finished_at_is_not_finished(self):
        run = {"id": "run-1", "status": "Running", "finishedAt": "2026-09-02T09:42:56Z"}
        self.assertFalse(is_finished(run))

    def test_finished_status_still_finishes_run(self):
        run = {"id": "run-1", "status": "finished", "finishedAt": None}
        self.assertTrue(is_finished(run))

    def test_failed_status_still_finishes_run(self):
        run = {"id": "run-1", "status": "failed", "finishedAt": None}
        self.assertTrue(is_finished(run))

    def test_finished_at_with_terminal_status_is_finished(self):
        run = {"id": "run-1", "status": "completed", "finishedAt": "2026-09-02T09:53:00Z"}
        self.assertTrue(is_finished(run))

    def test_stopped_status_is_finished(self):
        run = {"id": "run-1", "status": "stopped", "finishedAt": None}
        self.assertTrue(is_finished(run))

    def test_finished_at_alone_is_finished(self):
        run = {"id": "run-1", "status": None, "finishedAt": "2026-09-02T09:53:00Z"}
        self.assertTrue(is_finished(run))


class ConnectionCheckJobSuccessTests(unittest.TestCase):
    def test_green_finished_connection_check_job_is_successful(self):
        self.assertTrue(is_successful_connection_check_job(GREEN_JOB))
        self.assertEqual(extract_successful_connection_targets([GREEN_JOB]), ["10.0.0.4"])

    def test_running_job_with_finished_at_is_not_successful(self):
        job = {**GREEN_JOB, "status": "assigned"}
        self.assertFalse(is_successful_connection_check_job(job))

    def test_aggregate_yellow_error_status_ignored_when_per_result_success(self):
        # d295469: the aggregate job-level errorStatus is no longer a gate;
        # per-connection results are authoritative. A job marked yellow at the
        # aggregate level is still successful if every connection result is green.
        job = {**GREEN_JOB, "errorStatus": "yellow"}
        self.assertTrue(is_successful_connection_check_job(job))
        self.assertEqual(extract_successful_connection_targets([job]), ["10.0.0.4"])

    def test_error_result_fails_the_job(self):
        job = {
            **GREEN_JOB,
            "connectionCheckResults": [{"status": "success", "errors": ["timeout"]}],
        }
        self.assertFalse(is_successful_connection_check_job(job))


class WaitForConnectionCheckTargetsTests(unittest.TestCase):
    def _client(self, runs: list[dict], jobs: list[dict]):
        client = object.__new__(MpVmClient)
        client.get_task_runs = MagicMock(return_value=runs)
        client.get_run_jobs = MagicMock(return_value=jobs)
        client.stop_scanner_task = MagicMock()
        return client

    def test_in_progress_run_with_green_jobs_keeps_polling_until_finished(self):
        # Run carries finishedAt while in progress; MPVM then reports it
        # finished. Targets collected along the way must be returned.
        in_progress = {
            "id": "run-1",
            "status": "inProgress",
            "finishedAt": "2026-09-02T09:42:56Z",
        }
        finished = {"id": "run-1", "status": "finished", "finishedAt": None}
        client = self._client([in_progress], [GREEN_JOB])
        client.get_task_runs.side_effect = [[in_progress], [in_progress], [finished]]
        client.get_run_jobs.side_effect = [[GREEN_JOB], [], [GREEN_JOB]]

        targets, message = client.wait_for_connection_check_targets(
            "token",
            "task-1",
            time_from="2026-09-02T09:42:50Z",
            timeout_seconds=300,
            stop_after_seconds=600,
            poll_seconds=0,
            jobs_limit=1000,
        )

        self.assertEqual(targets, ["10.0.0.4"])
        self.assertEqual(message, "run run-1")
        self.assertGreaterEqual(client.get_task_runs.call_count, 3)

    def test_finished_run_without_successful_jobs_reports_no_success(self):
        run = {"id": "run-1", "status": "finished", "finishedAt": None}
        client = self._client([run], [])

        targets, message = client.wait_for_connection_check_targets(
            "token",
            "task-1",
            time_from="2026-09-02T09:42:50Z",
            timeout_seconds=300,
            stop_after_seconds=600,
            poll_seconds=0,
            jobs_limit=1000,
        )

        self.assertEqual(targets, [])
        self.assertIn("no jobs with full connection success", message)

    def test_timeout_returns_targets_collected_during_polling(self):
        # The 2026-09-02 incident: the run never reached a terminal state
        # within the timeout, but green connection-check jobs were present
        # in every poll. The collected targets must survive the timeout
        # instead of being discarded (which produced precheck_failed with
        # successful_targets=[] while MPVM showed green subtasks).
        in_progress = {"id": "run-1", "status": "running", "finishedAt": None}
        client = self._client([in_progress], [GREEN_JOB])

        targets, message = client.wait_for_connection_check_targets(
            "token",
            "task-1",
            time_from="2026-09-02T09:42:50Z",
            timeout_seconds=0.1,
            stop_after_seconds=0,
            poll_seconds=0.02,
            jobs_limit=1000,
        )

        self.assertEqual(targets, ["10.0.0.4"])
        self.assertIn("timeout after", message)
        self.assertIn("using 1 successful target(s)", message)
        self.assertEqual(client.stop_scanner_task.call_count, 0)

    def test_timeout_without_any_targets_still_fails(self):
        in_progress = {"id": "run-1", "status": "running", "finishedAt": None}
        client = self._client([in_progress], [])

        targets, message = client.wait_for_connection_check_targets(
            "token",
            "task-1",
            time_from="2026-09-02T09:42:50Z",
            timeout_seconds=0.1,
            stop_after_seconds=0,
            poll_seconds=0.02,
            jobs_limit=1000,
        )

        self.assertEqual(targets, [])
        self.assertIn("timeout after", message)


if __name__ == "__main__":
    unittest.main()
