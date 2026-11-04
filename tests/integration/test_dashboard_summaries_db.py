"""Dashboard aggregates and the stale-operation sweep run against real PostgreSQL."""
from datetime import UTC, datetime, timedelta

import pytest

from app import db
from app.repositories.operations import OperationsRepository
from app.repositories.risk import RiskRepository
from app.repositories.vm_workflows import VmWorkflowRepository

pytestmark = pytest.mark.integration


def seed_cases(rows):
    now = db.now_utc()
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO asset_cards(asset_id,display_name,first_seen,last_seen) VALUES('a','a',%s,%s)",
            (now, now),
        )
        for case_id, severity, status, due in rows:
            conn.execute(
                "INSERT INTO remediation_cases(case_id,asset_id,vulnerability_key,severity,status,due_at) "
                "VALUES(%s,'a',%s,%s,%s,%s)",
                (case_id, case_id, severity, status, due),
            )


def test_overview_lists_overdue_cases_first_then_by_severity_and_caps_at_ten(test_db):
    past = datetime.now(UTC) - timedelta(days=3)
    future = datetime.now(UTC) + timedelta(days=3)
    rows = [("late-low", "low", "open", past), ("late-crit", "critical", "in_progress", past)]
    rows += [(f"soon-{i:02}", "high" if i % 2 else "medium", "open", future + timedelta(hours=i)) for i in range(12)]
    rows += [("no-due-crit", "critical", "open", None), ("done", "critical", "resolved", past)]
    seed_cases(rows)

    result = VmWorkflowRepository().overview()

    assert [item["case_id"] for item in result["attention"][:2]] == ["late-crit", "late-low"]
    assert result["attention"][2]["case_id"] == "no-due-crit"
    assert len(result["attention"]) == 10
    assert "done" not in [item["case_id"] for item in result["attention"]]
    assert (result["open_cases"], result["overdue_cases"], result["asset_count"]) == (15, 2, 1)


def test_risk_summary_counts_every_open_case_not_only_the_first_page(test_db):
    seed_cases([(f"case-{i:03}", "low", "open", None) for i in range(520)])
    summary = RiskRepository().summary()
    assert summary["total"] == 520 and summary["low"] + summary["medium"] + summary["high"] + summary["urgent"] == 520


def register(operation_id, status, updated_at):
    db.register_operation(
        operation_id, kind="pdql_export", source_id=operation_id, status=status, stage=status,
        created_at=updated_at, updated_at=updated_at,
    )


def test_stale_active_operations_are_interrupted_and_recent_ones_are_kept(test_db):
    old = (datetime.now(UTC) - timedelta(hours=db.STALE_OPERATION_HOURS + 1)).isoformat(timespec="seconds")
    register("stuck", "running", old)
    register("stuck-queued", "queued", old)
    register("fresh", "running", db.now_utc())
    register("old-but-done", "completed", old)

    assert db.interrupt_stale_operations() == 2

    statuses = {item["operation_id"]: item["status"] for item in db.list_operations(limit=50)["rows"]}
    assert statuses == {
        "stuck": "interrupted", "stuck-queued": "interrupted", "fresh": "running", "old-but-done": "completed",
    }
    detail = db.get_operation("stuck")
    assert detail["finished_at"] and "6" in detail["message"]
    assert detail["events"][-1]["status"] == "interrupted"
    assert db.interrupt_stale_operations() == 0


def test_operations_summary_stops_counting_stuck_rows_as_active(test_db):
    old = (datetime.now(UTC) - timedelta(hours=db.STALE_OPERATION_HOURS + 2)).isoformat(timespec="seconds")
    for index in range(3):
        register(f"stuck-{index}", "running", old)
    register("alive", "running", db.now_utc())

    summary = OperationsRepository().summary()

    assert summary["active"] == 1
    assert summary["by_status"]["interrupted"] == 3
