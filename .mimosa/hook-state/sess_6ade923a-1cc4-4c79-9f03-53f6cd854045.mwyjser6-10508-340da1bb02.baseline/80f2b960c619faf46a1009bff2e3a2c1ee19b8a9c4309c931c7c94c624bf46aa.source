"""A fake remote transport exercises scheduled refreshes against real PostgreSQL."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.persistence import codecs
from app import db, main
from app.core.config import Settings
from app.repositories import passport_refresh
from app.services.passport_scheduler import PassportSyncScheduler
from app.services.vulnerability_passport_jobs import run_periodic_vulnerability_passport_refresh_job

pytestmark = pytest.mark.integration


@pytest.fixture
def periodic(test_db, monkeypatch):
    clock = [datetime(2026, 11, 8, 10, tzinfo=UTC)]
    monkeypatch.setattr(codecs, "now_utc", lambda: clock[0].isoformat(timespec="seconds"))
    state = SimpleNamespace(
        records=[{"@VulnerPassport": {"internalId": "p1", "id": "EXT-1", "name": "one"},
                  "VulnerPassport.PackageId": "pkg", "VulnerPassport.PackageVersion": "1"}],
        details={"p1": {"name": "one", "description": "old"}},
        fetched=[], catalog_calls=0, total=None, detail_error=None, parent_cancel=False,
    )

    class Client:
        def __init__(self, auth=None):
            self.auth = auth or SimpleNamespace()
            self.session = SimpleNamespace(close=lambda: None)

        def create_pdql_token(self, *_args, **_kwargs):
            state.catalog_calls += 1
            return "fake-pdql"

        def fetch_asset_grid_data(self, _token, _pdql, *, limit, offset):
            return {"records": state.records[offset:offset + limit],
                    "total": len(state.records) if state.total is None else state.total}

        def get_vulnerability_passport(self, _token, identifier):
            state.fetched.append(identifier)
            if state.parent_cancel:
                active = passport_refresh.latest()
                main.CONTAINER.operation_runner.cancellations.cancel("passport-refresh", active["operation_id"])
            if state.detail_error:
                raise RuntimeError(state.detail_error)
            return state.details[identifier]

    client = Client()
    monkeypatch.setattr(main, "MpVmClient", Client)
    monkeypatch.setattr(main, "require_mpvm", lambda: (client, "fake-token"))
    monkeypatch.setattr(main, "sync_trending_vulnerability_passports", lambda **_: {"status": "completed"})
    monkeypatch.setattr(main, "PASSPORT_DETAIL_WORKERS", 1)
    runner = main.CONTAINER.operation_runner
    scheduler = PassportSyncScheduler(
        settings=Settings(_env_file=None, passport_sync_enabled=True, passport_sync_interval_seconds=60),
        runner=runner, ready=lambda: True, execute=run_periodic_vulnerability_passport_refresh_job,
    )
    return SimpleNamespace(clock=clock, state=state, scheduler=scheduler,
                           tick=lambda: scheduler.tick(now=clock[0]))


def test_periodic_detects_details_only_change_and_new_passport(periodic):
    periodic.tick()
    first = passport_refresh.latest()
    assert first["status"] == "completed"
    assert first["request"]["trigger"] == "periodic"
    assert first["result"]["detail_job"]["status"] == "completed"
    assert db.get_vulnerability_passport("p1")["raw_detail"]["description"] == "old"
    periodic.tick()
    assert periodic.state.catalog_calls == 1
    periodic.clock[0] += timedelta(seconds=60)
    periodic.state.details["p1"] = {"name": "one", "description": "only detail changed"}
    periodic.state.records.append({"@VulnerPassport": {"internalId": "p2", "id": "EXT-2", "name": "two"}})
    periodic.state.details["p2"] = {"name": "two", "description": "new"}
    periodic.tick()
    assert db.get_vulnerability_passport("p1")["raw_detail"]["description"] == "only detail changed"
    assert db.get_vulnerability_passport("p2")["raw_detail"]["description"] == "new"
    second = passport_refresh.latest()
    assert second["operation_id"] != first["operation_id"]
    assert second["result"]["detail_job"]["loaded_count"] == 2
    periodic.clock[0] += timedelta(seconds=60)
    periodic.tick()
    assert passport_refresh.latest()["result"]["db"]["changed"] == 0
    assert db.list_vulnerability_passports()["total"] == 2


def test_periodic_incomplete_catalog_preserves_previous_data(periodic):
    periodic.tick()
    before = db.get_vulnerability_passport("p1")["raw_detail"]
    periodic.clock[0] += timedelta(seconds=60)
    periodic.state.total = 2
    periodic.state.details["p1"] = {"description": "must not save"}
    periodic.tick()
    assert passport_refresh.latest()["status"] == "failed"
    assert db.get_vulnerability_passport("p1")["raw_detail"] == before
    assert periodic.state.fetched == ["p1"]
    periodic.tick()
    assert periodic.state.catalog_calls == 2


def test_periodic_individual_detail_error_preserves_previous_version(periodic):
    periodic.tick()
    periodic.clock[0] += timedelta(seconds=60)
    periodic.state.detail_error = "fake timeout"
    periodic.tick()
    operation = passport_refresh.latest()
    assert operation["status"] == "completed_with_errors"
    assert operation["result"]["detail_job"]["failed_count"] == 1
    assert db.get_vulnerability_passport("p1")["raw_detail"]["description"] == "old"
    periodic.state.detail_error = None
    periodic.clock[0] += timedelta(seconds=60)
    periodic.tick()
    assert passport_refresh.latest()["status"] == "completed"


def test_periodic_parent_cancel_and_restart_are_recoverable(periodic):
    periodic.state.parent_cancel = True
    periodic.tick()
    operation = passport_refresh.latest()
    assert operation["status"] == "cancelled"
    assert operation["result"]["detail_job"]["status"] == "cancelled"
    periodic.state.parent_cancel = False
    periodic.tick()
    assert periodic.state.catalog_calls == 1
    periodic.clock[0] += timedelta(seconds=60)
    abandoned = passport_refresh.reserve_periodic({}, now=periodic.clock[0], interval_seconds=60)
    assert abandoned is not None
    assert passport_refresh.interrupt_active() == 1
    periodic.clock[0] += timedelta(seconds=1)
    periodic.tick()
    assert passport_refresh.latest()["status"] == "completed"
    assert db.list_vulnerability_passports()["total"] == 1


def test_periodic_reissue_moves_finding_and_remediation_links(periodic):
    periodic.tick()
    now = db.now_utc()
    with db.connect() as conn:
        conn.execute("INSERT INTO asset_cards(asset_id,display_name,first_seen,last_seen) VALUES('a','host',%s,%s)", (now, now))
        group_id = conn.execute(
            "INSERT INTO asset_card_vulnerability_groups(asset_id,source_type,collection_type,collection_id,group_order,updated_at) "
            "VALUES('a','host','c','g',0,%s) RETURNING id", (now,),
        ).fetchone()["id"]
        finding = conn.execute(
            "INSERT INTO asset_card_vulnerabilities(asset_id,group_id,vulnerability_instance_id,vulnerability_id,updated_at) "
            "VALUES('a',%s,'instance','p1',%s) RETURNING id", (group_id, now),
        ).fetchone()["id"]
        db.reconcile_asset_card_vulnerability_passport_links(conn, ["p1"], now)
        conn.execute(
            "INSERT INTO remediation_cases(case_id,asset_id,vulnerability_key,status,passport_internal_id) "
            "VALUES('case','a','finding','open','p1')",
        )
    periodic.clock[0] += timedelta(seconds=60)
    periodic.state.records = [{"@VulnerPassport": {"internalId": "p1-new", "id": "EXT-1", "name": "one"},
                               "VulnerPassport.PackageId": "pkg", "VulnerPassport.PackageVersion": "1"}]
    periodic.state.details["p1-new"] = {"name": "one", "description": "replacement"}
    periodic.tick()
    assert passport_refresh.latest()["status"] == "completed"
    assert passport_refresh.latest()["result"]["db"]["replaced"] == 1
    assert db.get_vulnerability_passport("p1") is None
    assert db.get_vulnerability_passport("p1-new")["raw_detail"]["description"] == "replacement"
    with db.connect() as conn:
        link = conn.execute("SELECT passport_internal_id FROM asset_card_vulnerability_passports WHERE asset_vulnerability_id=%s", (finding,)).fetchone()
        assert link["passport_internal_id"] == "p1-new"
        assert conn.execute("SELECT passport_internal_id FROM remediation_cases WHERE case_id='case'").fetchone()["passport_internal_id"] == "p1-new"


def test_unknown_total_does_not_replace_or_remove_existing_passports(periodic, monkeypatch):
    periodic.tick()
    periodic.clock[0] += timedelta(seconds=60)
    periodic.state.records = [{"@VulnerPassport": {"internalId": "p1-new", "id": "EXT-1", "name": "one"},
                               "VulnerPassport.PackageId": "pkg", "VulnerPassport.PackageVersion": "1"}]
    periodic.state.details["p1-new"] = {"name": "one", "description": "new evidence"}
    monkeypatch.setattr(main, "fetch_asset_grid_records", lambda **_: (periodic.state.records, {
        "reportedTotal": None, "batches": [{"reported_total": None}],
    }))
    periodic.tick()
    assert passport_refresh.latest()["status"] == "completed"
    assert passport_refresh.latest()["result"]["db"]["replaced"] == 0
    assert db.get_vulnerability_passport("p1") is not None
    assert db.get_vulnerability_passport("p1-new")["raw_detail"]["description"] == "new evidence"


def test_force_candidates_keeps_normal_ttl_and_deduplicates(periodic):
    periodic.tick()
    assert db.vulnerability_passport_detail_refresh_candidates(["p1"], ttl_hours=24)["eligible"] == []
    assert db.vulnerability_passport_detail_refresh_candidates(["p1", "p1", None], ttl_hours=24, force=True) == {
        "requested": ["p1"], "eligible": ["p1"], "skipped_fresh": [],
    }
    assert db.vulnerability_passport_detail_refresh_candidates([], ttl_hours=24, force=True)["eligible"] == []
