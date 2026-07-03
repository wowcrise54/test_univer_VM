from __future__ import annotations

import threading
import time
import unittest

from app.jobs import JobRunner


class JobRunnerTests(unittest.TestCase):
    def test_duplicate_job_is_not_submitted_twice(self):
        release = threading.Event()
        started = threading.Event()
        runner = JobRunner({"fixture": 1}, session_ready=lambda: True)
        try:
            self.assertTrue(runner.submit("fixture", "job-1", lambda: (started.set(), release.wait(1))))
            self.assertTrue(started.wait(1))
            self.assertFalse(runner.submit("fixture", "job-1", lambda: None))
        finally:
            release.set()
            runner.shutdown(wait=True)

    def test_job_waits_until_session_is_ready(self):
        ready = False
        completed = threading.Event()
        runner = JobRunner({"fixture": 1}, session_ready=lambda: ready)
        try:
            self.assertTrue(runner.submit("fixture", "job-1", completed.set))
            self.assertFalse(completed.wait(0.05))
            self.assertEqual(runner.telemetry()["waiting_for_session"][0]["job_id"], "job-1")
            ready = True
            self.assertEqual(runner.notify_session_ready(), 1)
            self.assertTrue(completed.wait(1))
        finally:
            runner.shutdown(wait=True)

    def test_heartbeat_runs_while_job_is_active(self):
        release = threading.Event()
        heartbeat = threading.Event()
        runner = JobRunner({"fixture": 1}, session_ready=lambda: True, heartbeat_seconds=1)
        try:
            runner.submit("fixture", "job-1", lambda: release.wait(2), heartbeat=heartbeat.set)
            self.assertTrue(heartbeat.wait(1))
        finally:
            release.set()
            runner.shutdown(wait=True)


if __name__ == "__main__":
    unittest.main()
