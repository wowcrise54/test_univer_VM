import json
from asyncio import run
from threading import Barrier, Event

import pytest
from fastapi import BackgroundTasks, HTTPException

from app import db
from app.api.passports import create_vulnerability_passport_refresh_job, export_wazuh_refresh_errors
from app.repositories import passport_refresh
from app.repositories.passports.wazuh_cti import create_passports, iter_refresh_failures
from app.services import wazuh_cti
from app.services.wazuh_asset_match import assess_asset

pytestmark = pytest.mark.integration


def test_bulk_refresh_only_visits_local_wazuh_passports(test_db, monkeypatch):
    cves = ["CVE-2025-1000", "CVE-2025-1001", "CVE-2025-1002"]
    db.upsert_vulnerability_passports([{"internal_id": "mpvm-a", "cves": cves}])
    create_passports()
    with db.connect() as conn:
        conn.execute(
            "UPDATE vulnerability_passports SET detail_updated_at = %s, raw_detail_json = %s WHERE internal_id = %s",
            (db.now_utc(), '{"rules_indexed":true}', "wazuh-cti:CVE-2025-1002"),
        )
    attempted = []
    concurrent = Barrier(2, timeout=5)

    def refresh(passport_id, *, session):
        assert isinstance(session, wazuh_cti.requests.Session)
        attempted.append(passport_id)
        concurrent.wait()
        if passport_id.endswith("1001"):
            raise HTTPException(404, "CVE not found")

    monkeypatch.setattr(wazuh_cti, "refresh_passport", refresh)
    tasks = BackgroundTasks()
    job = create_vulnerability_passport_refresh_job(tasks, source="wazuh-cti")["job"]
    task = tasks.tasks[0]
    task.func(*task.args, **task.kwargs)
    completed = passport_refresh.get(job["operation_id"])
    assert sorted(attempted) == [f"wazuh-cti:{cve}" for cve in cves[:2]]
    assert completed["status"] == "completed_with_errors"
    assert completed["result"]["wazuh_cti"] == {
        "total": 3, "updated": 1, "failed": 1, "skipped_fresh": 1,
    }
    assert list(iter_refresh_failures(job["operation_id"])) == [
        {"passport_id": "wazuh-cti:CVE-2025-1001", "status_code": 404, "attempts": 1, "reason": "CVE not found"},
    ]
    response = export_wazuh_refresh_errors(job["operation_id"])

    async def read_csv():
        return "".join([chunk async for chunk in response.body_iterator])

    assert "CVE-2025-1001,404,1,CVE not found" in run(read_csv())


def test_bulk_reuses_session_and_stops_on_rate_limit(monkeypatch):
    sessions = []
    updates = []
    monkeypatch.setattr(wazuh_cti, "refresh_candidates", lambda ttl: (["a", "b", "c"], 0))
    monkeypatch.setattr(wazuh_cti, "WAZUH_REFRESH_WORKERS", 1)
    monkeypatch.setattr(passport_refresh, "update", lambda operation_id, **fields: updates.append(fields))
    monkeypatch.setattr(wazuh_cti, "record_refresh_failures", lambda operation_id, failures: None)

    def refresh(passport_id, *, session):
        sessions.append(session)
        if passport_id == "b":
            raise HTTPException(429, "Rate limit")

    monkeypatch.setattr(wazuh_cti, "refresh_passport", refresh)
    wazuh_cti.refresh_local_passports("operation", Event())

    assert len(sessions) == 2
    assert sessions[0] is sessions[1]
    assert updates[-1]["status"] == "completed_with_errors"
    assert updates[-1]["percent"] == 66


@pytest.mark.parametrize("recovers", [True, False])
def test_transient_wazuh_error_retries_only_within_limit(monkeypatch, recovers):
    attempted = []
    retries = Event()
    monkeypatch.setattr(retries, "wait", lambda delay: False)

    def refresh(passport_id, *, session):
        attempted.append(passport_id)
        if not recovers or len(attempted) < 2:
            raise wazuh_cti.TransientWazuhError(502, "Timeout")

    monkeypatch.setattr(wazuh_cti, "refresh_passport", refresh)
    with wazuh_cti.requests.Session() as session:
        failure = wazuh_cti._refresh_with_retries("wazuh-cti:CVE-2025-1000", session, retries, Event())
    assert attempted == ["wazuh-cti:CVE-2025-1000"] * (2 if recovers else 3)
    assert failure == (None if recovers else ("wazuh-cti:CVE-2025-1000", 502, 3, "Timeout"))


def test_bulk_wazuh_has_64_worker_slots(monkeypatch):
    pending_sizes = []
    real_wait = wazuh_cti.wait
    monkeypatch.setattr(wazuh_cti, "refresh_candidates", lambda ttl: ([str(i) for i in range(65)], 0))
    monkeypatch.setattr(passport_refresh, "update", lambda operation_id, **fields: None)
    monkeypatch.setattr(wazuh_cti, "refresh_passport", lambda passport_id, *, session: None)

    def observe_pending(futures, **kwargs):
        pending_sizes.append(len(futures))
        return real_wait(futures, **kwargs)

    monkeypatch.setattr(wazuh_cti, "wait", observe_pending)
    wazuh_cti.refresh_local_passports("operation", Event())

    assert max(pending_sizes) == 64


def test_wazuh_passport_is_unique_and_caches_cti(test_db, monkeypatch):
    cve = "CVE-2025-49796"
    passport_id = f"wazuh-cti:{cve}"
    db.upsert_vulnerability_passports([
        {"internal_id": "mpvm-a", "cves": [cve]},
        {"internal_id": "mpvm-b", "cves": [cve.lower()]},
    ])
    assert create_passports() == 1
    assert create_passports() == 0
    assert db.get_vulnerability_passport(passport_id)["cves"][0]["display_name"] == cve

    document = {
        "cveMetadata": {"cveId": cve, "datePublished": "2025-06-16"},
        "containers": {"cna": {
            "descriptions": [{"lang": "en", "value": "Test description."}],
            "metrics": [{"cvssV3_1": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}}],
            "references": [{"url": "https://example.com/advisory"}],
            "providerMetadata": {"shortName": "debian"},
            "affected": [{
                "vendor": "debian", "product": "example", "platforms": ["bookworm"],
                "defaultStatus": "unaffected",
                "versions": [{"status": "affected", "version": "0", "lessThan": "2.0-2", "versionType": "deb"}],
            }],
        }},
    }

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return document

    monkeypatch.setattr(wazuh_cti.requests, "get", lambda *args, **kwargs: Response())
    saved = wazuh_cti.refresh_passport(passport_id)
    assert "record" not in saved["raw_detail"]
    assert saved["raw_detail"]["references"] == ["https://example.com/advisory"]
    assert saved["raw_detail"]["description"] == "Test description."
    assert saved["score"] == "9.1"
    db.upsert_asset_card({
        "asset_id": "linux-test",
        "root": {"objectId": "linux-test", "data": {"osName": "Debian", "osVersion": "12.15"}},
        "collections": [{
            "name": "packages", "path": "packages", "parent_object_id": "linux-test",
            "count": 2, "fetched_count": 2, "truncated": False,
            "items": [
                {"type": "OperatingSystem.UNIX.Linux.Debian.DebianPackage",
                 "data": {"name": "example", "version": version}}
                for version in ("2.0-1", "2.0-2")
            ],
        }],
    })
    result = assess_asset("linux-test")
    assert result["inventory_complete"]
    assert result["evaluated_packages"] == 2
    assert [(item["passport_id"], item["version"]) for item in result["matches"]] == [(passport_id, "2.0-1")]

    def unavailable(*args, **kwargs):
        raise wazuh_cti.requests.Timeout

    monkeypatch.setattr(wazuh_cti.requests, "get", unavailable)
    with pytest.raises(HTTPException) as error:
        wazuh_cti.refresh_passport(passport_id)
    assert error.value.status_code == 502
    with db.connect() as conn:
        stored = conn.execute(
            "SELECT raw_detail_json FROM vulnerability_passports WHERE internal_id = %s",
            (passport_id,),
        ).fetchone()
        detail = json.loads(stored["raw_detail_json"])
        assert "record" not in detail
        conn.execute(
            "UPDATE vulnerability_passports SET raw_detail_json = %s WHERE internal_id = %s",
            (json.dumps({**detail, "record": document}), passport_id),
        )
    assert db.get_vulnerability_passport(passport_id)["raw_detail"] == detail
