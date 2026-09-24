from __future__ import annotations

import threading
from unittest.mock import Mock, patch

from app import main
from app.api.schemas import VulnerabilityPassportQueryRequest
from app.services import passport_refresh as service


def test_grid_fetch_reports_real_loaded_count_and_total():
    client = Mock()
    client.fetch_asset_grid_data.side_effect = [
        {"records": [{"id": "one"}, {"id": "two"}], "total": 3},
        {"records": [{"id": "three"}], "total": 3},
    ]
    progress = Mock()
    records, _ = main.fetch_asset_grid_records(
        client=client, token="token", pdql_token="pdql",
        limit=None, batch_size=2, progress_callback=progress,
    )
    assert len(records) == 3
    assert progress.call_args_list[0].args == (2, 3)
    assert progress.call_args_list[1].args == (3, 3)


def test_refresh_worker_records_completion_and_queues_detail_job():
    payload = VulnerabilityPassportQueryRequest()
    submit = Mock()

    def execute_query(_payload, tasks, progress):
        progress(75, "fetch", "Получено 10 из 10 паспортов.")
        tasks.add_task(lambda: None)
        return {"total": 10, "db": {"saved": 10}, "detail_job": {"job_id": "detail"}}

    with patch.object(service.passport_refresh, "update") as update:
        service.run("catalog", payload, execute_query, submit, threading.Event())

    assert update.call_args.kwargs["status"] == "completed"
    assert update.call_args.kwargs["percent"] == 100
    assert update.call_args.kwargs["result"]["db"]["saved"] == 10
    submit.assert_called_once()


def test_refresh_worker_stops_before_next_batch_when_cancelled():
    cancel = threading.Event()

    def execute_query(_payload, _tasks, progress):
        cancel.set()
        progress(30, "fetch", "Получено 30 паспортов.")

    with patch.object(service.passport_refresh, "update") as update:
        service.run("catalog", VulnerabilityPassportQueryRequest(), execute_query, Mock(), cancel)

    assert update.call_args.kwargs["status"] == "cancelled"
