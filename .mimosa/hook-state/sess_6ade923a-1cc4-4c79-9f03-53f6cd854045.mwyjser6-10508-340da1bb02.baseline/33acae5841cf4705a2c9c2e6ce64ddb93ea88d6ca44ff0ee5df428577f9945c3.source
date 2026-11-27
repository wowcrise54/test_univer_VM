from __future__ import annotations

import psycopg
import pytest

from app import db
from app.repositories.scanner_task_folders import ScannerTaskFolderRepository
from app.services.scanner_task_folders import ScannerTaskFolderService


def test_shared_folder_assignments_are_unique_audited_and_unassigned_on_delete(test_db):
    service = ScannerTaskFolderService(ScannerTaskFolderRepository())
    folder = service.create("Production", actor="operator")
    folder_id = folder["folder_id"]

    service.assign(["task-1", "task-2"], folder_id, actor="operator")
    service.assign(["task-1"], None, actor="admin")

    rows = service.list()["rows"]
    assert rows == [{"folder_id": folder_id, "name": "Production", "task_ids": ["task-2"]}]
    other = service.create("Another folder", actor="admin")
    service.assign(["task-2"], other["folder_id"], actor="operator")
    by_name = {row["name"]: row["task_ids"] for row in service.list()["rows"]}
    assert by_name["Production"] == []
    assert by_name["Another folder"] == ["task-2"]

    with pytest.raises(psycopg.errors.UniqueViolation):
        service.create("production", actor="admin")

    with db.connect() as conn:
        assignment = conn.execute(
            "SELECT updated_by FROM scanner_task_folder_assignments WHERE task_id='task-2'"
        ).fetchone()
        assert assignment["updated_by"] == "operator"

    service.delete(other["folder_id"], actor="operator")
    service.delete(folder_id, actor="operator")
    assert service.list()["rows"] == []


def test_folder_names_are_trimmed_and_blank_names_rejected(test_db):
    service = ScannerTaskFolderService(ScannerTaskFolderRepository())
    folder = service.create("  Nightly  ", actor="operator")
    assert folder["name"] == "Nightly"
    with pytest.raises(ValueError, match="cannot be empty"):
        service.create("   ", actor="operator")
