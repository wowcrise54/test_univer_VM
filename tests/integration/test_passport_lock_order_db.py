from concurrent.futures import ThreadPoolExecutor
from threading import Event, current_thread
from time import monotonic, sleep
from unittest.mock import patch

import pytest

from app import db
from app.diagnostics import DiagnosticConnection


@pytest.mark.parametrize("refresh", ["snapshot", "detail_links"])
@pytest.mark.parametrize("write", ["upsert", "cache", "delete"])
def test_passport_refresh_and_card_writes_do_not_deadlock(test_db, refresh, write):
    card = {
        "asset_id": "host-1",
        "vulnerabilities": {"sources": [{
            "source": "os", "collection_type": "os", "groups": [{
                "collection_id": "os-1", "items": [{
                    "vulnerability_id": "passport-1", "vulnerability_instance_id": "finding-1",
                }],
            }],
        }]},
    }
    db.upsert_vulnerability_passports([{"internal_id": "passport-1"}])
    db.upsert_asset_card(card)
    links_deleted = Event()
    resume_refresh = Event()
    writer_connected = Event()
    writer_pid = []
    original_connect = db.connect
    original_execute = DiagnosticConnection.execute

    def connect():
        conn = original_connect()
        conn.execute("SET statement_timeout = '10s'")
        conn.execute("SET deadlock_timeout = '100ms'")
        if current_thread().name.startswith("card-writer"):
            writer_pid.append(conn.info.backend_pid)
            writer_connected.set()
        return conn

    def execute(conn, query, *args, **kwargs):
        result = original_execute(conn, query, *args, **kwargs)
        if (current_thread().name.startswith("passport-refresh")
                and "DELETE FROM asset_card_vulnerability_passports AS link" in str(query)):
            links_deleted.set()
            assert resume_refresh.wait(10), "Refresh was not released"
        return result

    def refresh_passports():
        if refresh == "snapshot":
            return db.upsert_vulnerability_passports([{"internal_id": "passport-1", "name": "Updated"}])
        return db.reconcile_vulnerability_passport_detail_job_links()

    def write_card():
        if write == "upsert":
            return db.upsert_asset_card(card)
        if write == "delete":
            return db.delete_asset_card("host-1")
        with db.connect() as conn:
            db.replace_asset_card_cache(conn, "host-1", card, db.now_utc())

    with (
        patch.object(db, "connect", side_effect=connect),
        patch.object(DiagnosticConnection, "execute", execute),
        ThreadPoolExecutor(max_workers=1, thread_name_prefix="passport-refresh") as refresher,
        ThreadPoolExecutor(max_workers=1, thread_name_prefix="card-writer") as writer,
    ):
        refresh_future = refresher.submit(refresh_passports)
        try:
            assert links_deleted.wait(10), "Refresh did not reach link reconciliation"
            write_future = writer.submit(write_card)
            assert writer_connected.wait(5)
            # Release only once PostgreSQL confirms the writer is waiting on
            # the refresh transaction, rather than relying on thread timing.
            with original_connect() as observer:
                deadline = monotonic() + 5
                while monotonic() < deadline:
                    blocked = observer.execute(
                        "SELECT cardinality(pg_blocking_pids(%s)) AS count", (writer_pid[0],)
                    ).fetchone()["count"]
                    if blocked:
                        break
                    sleep(0.01)
                assert blocked, "Concurrent card writer never waited on refresh locks"
        finally:
            resume_refresh.set()
        refresh_future.result(timeout=15)
        write_future.result(timeout=15)

    with original_connect() as conn:
        findings = conn.execute("SELECT count(*) AS count FROM asset_card_vulnerabilities").fetchone()["count"]
        links = conn.execute("SELECT count(*) AS count FROM asset_card_vulnerability_passports").fetchone()["count"]
    assert findings == links == (0 if write == "delete" else 1)
