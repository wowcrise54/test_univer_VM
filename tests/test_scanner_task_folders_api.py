from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

import psycopg
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import auth
from app.api import scanner_task_folders

FOLDER_ID = str(uuid4())


@pytest.fixture
def service():
    return MagicMock()


@pytest.fixture
def client(service):
    app = FastAPI()
    app.include_router(scanner_task_folders.router)
    app.state.container = SimpleNamespace(services=SimpleNamespace(scanner_task_folders=service))
    with patch.object(auth, "audit_event") as audit:
        yield TestClient(app, raise_server_exceptions=False), audit


def test_folder_lifecycle_delegates_to_service_and_audits(client, service):
    http, audit = client
    service.list.return_value = {"rows": []}
    service.create.return_value = {"folder_id": FOLDER_ID, "name": "Prod"}
    service.rename.return_value = {"folder_id": FOLDER_ID, "name": "Stage"}

    assert http.get("/api/scanner-task-folders").json() == {"rows": []}
    assert http.post("/api/scanner-task-folders", json={"name": " Prod "}).status_code == 201
    service.create.assert_called_once_with("Prod", actor=None)
    assert http.patch(f"/api/scanner-task-folders/{FOLDER_ID}", json={"name": "Stage"}).json()["name"] == "Stage"
    assert http.delete(f"/api/scanner-task-folders/{FOLDER_ID}").json() == {"deleted": True}
    response = http.put("/api/scanner-task-folders/assignments", json={"task_ids": [" a ", "a", "b"], "folder_id": None})
    assert response.json() == {"assigned": 2, "folder_id": None}
    service.assign.assert_called_once_with(["a", "b"], None, actor=None)
    assert [call.kwargs["event_type"] for call in audit.call_args_list] == [
        "task_folder_created", "task_folder_renamed", "task_folder_deleted", "task_folder_assignments_changed",
    ]


def test_blank_names_and_task_ids_are_rejected_before_the_service(client, service):
    http, _ = client
    assert http.post("/api/scanner-task-folders", json={"name": "   "}).status_code == 422
    response = http.put("/api/scanner-task-folders/assignments", json={"task_ids": ["  "], "folder_id": FOLDER_ID})
    assert response.status_code == 422
    service.create.assert_not_called()
    service.assign.assert_not_called()


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (LookupError("Task folder not found."), 404, "TASK_FOLDER_NOT_FOUND"),
        (ValueError("bad name"), 422, "INVALID_TASK_FOLDER"),
        (psycopg.errors.UniqueViolation(), 409, "TASK_FOLDER_NAME_EXISTS"),
    ],
)
def test_domain_errors_map_to_http_codes(client, service, error, status, code):
    http, audit = client
    service.rename.side_effect = error
    response = http.patch(f"/api/scanner-task-folders/{FOLDER_ID}", json={"name": "Stage"})
    assert response.status_code == status
    assert response.json()["detail"]["code"] == code
    audit.assert_not_called()


def test_unexpected_errors_are_not_masked(client, service):
    http, _ = client
    service.delete.side_effect = RuntimeError("boom")
    assert http.delete(f"/api/scanner-task-folders/{FOLDER_ID}").status_code == 500
