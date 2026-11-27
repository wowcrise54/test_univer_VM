from __future__ import annotations

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app import db, main
from app.api.scanner_task_runs import scanner_task_run_jobs, scanner_task_runs


class FakeMpVmClient:
    def __init__(self):
        self.job_reads: list[str] = []

    def get_task_runs(self, _token, task_id, *, offset=0, limit=1):
        assert offset >= 0
        assert limit > 0
        return [{"id": "run-1", "startedAt": "2026-10-02T10:00:00Z"}] if task_id == "task-1" else []

    def get_all_run_jobs(self, _token, run_id, **_options):
        self.job_reads.append(run_id)
        return [{"id": "job-1", "status": "finished"}]


def _request() -> Request:
    return Request({"type": "http", "app": main.app, "state": {}})


def test_task_run_history_is_paged_and_jobs_require_task_ownership(test_db, monkeypatch):
    db.record_scan_task(mp_task_id="task-1", payload={"name": "Audit"}, status="created")
    fake_client = FakeMpVmClient()
    monkeypatch.setattr(main.CONTAINER.session, "client", fake_client)
    monkeypatch.setattr(main.CONTAINER.session, "access_token", "test-token")

    page = scanner_task_runs(_request(), "task-1", offset=20, limit=10)
    assert page == {
        "items": [{"id": "run-1", "startedAt": "2026-10-02T10:00:00Z"}],
        "total": 1,
        "offset": 20,
        "limit": 10,
        "has_more": False,
    }
    with pytest.raises(HTTPException) as not_found:
        scanner_task_run_jobs(_request(), "task-1", "run-from-another-task")
    assert not_found.value.status_code == 404
    assert fake_client.job_reads == []

    jobs = scanner_task_run_jobs(_request(), "task-1", "run-1")
    assert jobs == {"items": [{"id": "job-1", "status": "finished"}], "total": 1}
    assert fake_client.job_reads == ["run-1"]
