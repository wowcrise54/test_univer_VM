import io
import json
from asyncio import run
from threading import Event
from zipfile import ZipFile

import pytest
from fastapi import BackgroundTasks, HTTPException

from app import db
from app.api.asset_cards import local_asset_wazuh_cti_matches
from app.api.passports import create_vulnerability_passport_refresh_job, export_wazuh_refresh_errors
from app.repositories import passport_refresh
from app.repositories.passports.wazuh_cti import create_passports, iter_refresh_failures
from app.services import wazuh_cti, wazuh_snapshot
from app.services.wazuh_asset_match import assess_asset
from app.services.wazuh_asset_scheduler import reconcile_due_assets

pytestmark = pytest.mark.integration


def test_bulk_snapshot_updates_local_passports_once_and_reports_invalid_records(test_db, monkeypatch, tmp_path):
    cves = ["CVE-2025-1000", "CVE-2025-1001", "CVE-2025-1002"]
    db.upsert_vulnerability_passports([{"internal_id": "mpvm-a", "cves": cves}])
    create_passports()
    cve = cves[0]
    payload = {
        "cveMetadata": {"cveId": cve},
        "containers": {"cna": {
            "providerMetadata": {"shortName": "debian"},
            "affected": [{
                "vendor": "debian", "product": "example", "platforms": ["bookworm"],
                "defaultStatus": "unaffected",
                "versions": [{"status": "affected", "version": "0", "lessThan": "2"}],
            }],
        }},
    }
    archive_bytes = io.BytesIO()
    records = [{"name": cve, "payload": payload}, {"name": cves[1], "payload": {}}]
    with ZipFile(archive_bytes, "w") as archive:
        archive.writestr("snapshot.json", "\n".join(json.dumps(row) for row in records))
    downloads = []
    snapshot = [1]

    def get(session, url, **kwargs):
        if url == wazuh_snapshot.CATALOG_URL:
            return FakeResponse(document={"data": {
                "last_snapshot_offset": snapshot[0],
                "last_snapshot_link": f"https://cti.wazuh.com/store/contexts/vd_1.0.0/test-{snapshot[0]}.zip",
            }})
        downloads.append(url)
        return FakeResponse(content=archive_bytes.getvalue())

    monkeypatch.setattr(wazuh_snapshot.requests.Session, "get", get)
    monkeypatch.setattr(wazuh_snapshot, "SNAPSHOT_CACHE", tmp_path)

    def run_job():
        tasks = BackgroundTasks()
        job = create_vulnerability_passport_refresh_job(tasks, source="wazuh-cti")["job"]
        task = tasks.tasks[0]
        task.func(*task.args, **task.kwargs)
        return passport_refresh.get(job["operation_id"])

    completed = run_job()
    assert completed["status"] == "completed_with_errors"
    assert completed["result"]["wazuh_cti"] == {
        "total": 3, "updated": 1, "failed": 1, "unchanged": 0,
        "outside_scope": 0, "not_in_snapshot": 1,
    }
    assert db.get_vulnerability_passport("mpvm-a")["raw_detail"] is None
    assert db.get_vulnerability_passport("wazuh-cti:" + cve)["raw_detail"]["cves"] == [cve]
    assert list(iter_refresh_failures(completed["operation_id"]))[0]["passport_id"] == "wazuh-cti:" + cves[1]
    response = export_wazuh_refresh_errors(completed["operation_id"])

    async def read_csv():
        return "".join([chunk async for chunk in response.body_iterator])

    assert f"{cves[1]},502,1," in run(read_csv())

    with ZipFile(archive_bytes := io.BytesIO(), "w") as archive:
        archive.writestr("snapshot.json", json.dumps(records[0]))
    snapshot[0] = 2
    result = run_job()
    assert result["status"] == "completed"
    assert result["result"]["wazuh_cti"]["unchanged"] == 1
    assert run_job()["status"] == "completed"
    assert len(downloads) == 2

    snapshot[0] = 3

    def unavailable(*args):
        raise wazuh_snapshot.SnapshotUnavailable("Range ignored")

    monkeypatch.setattr(wazuh_snapshot, "download_snapshot", unavailable)
    fallback_requests = []

    def get_cve(url, **kwargs):
        fallback_requests.append(url)
        cve_id = url.split("/")[-2]
        return FakeResponse(document={"cveMetadata": {"cveId": cve_id}, "containers": {}})

    def get_with_fallback(session, url, **kwargs):
        return get_cve(url, **kwargs) if url.endswith("/json5") else get(session, url, **kwargs)

    monkeypatch.setattr(wazuh_snapshot.requests.Session, "get", get_with_fallback)
    fallback_job = run_job()
    assert fallback_job["status"] == "completed"
    assert fallback_job["result"]["mode"] == "per-cve"
    assert fallback_job["result"]["wazuh_cti"]["updated"] == 2
    assert len(fallback_requests) == 2


class FakeResponse:
    status_code = 200

    def __init__(self, *, content=b"", document=None):
        self.content = content
        self.document = document
        self.headers = {"Content-Length": str(len(content)), "ETag": '"snapshot"'}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def raise_for_status(self):
        pass

    def json(self):
        return self.document

    def iter_content(self, chunk_size):
        yield self.content



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
    card = {
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
    }
    db.upsert_asset_card(card)
    result = assess_asset("linux-test")
    assert result["inventory_complete"]
    assert result["evaluated_packages"] == 2
    assert [(item["passport_id"], item["version"]) for item in result["matches"]] == [(passport_id, "2.0-1")]
    assert assess_asset("linux-test", additional_only=True)["matches"] == result["matches"]
    assert local_asset_wazuh_cti_matches("linux-test")["pending"]
    reconcile_due_assets(Event())
    saved_result = local_asset_wazuh_cti_matches("linux-test", additional_only=True)
    assert saved_result["checked_at"]
    assert saved_result["matches"] == result["matches"]
    assert saved_result["passports"][passport_id]["cvss_score"] == "9.1"

    refreshed_card = db.upsert_asset_card(card)
    assert local_asset_wazuh_cti_matches("linux-test")["pending"]
    stopped = Event()
    stopped.set()
    reconcile_due_assets(stopped)
    assert local_asset_wazuh_cti_matches("linux-test")["pending"]
    reconcile_due_assets(Event())
    assert local_asset_wazuh_cti_matches("linux-test")["inventory_at"] == refreshed_card["last_seen"]
    with db.connect() as conn:
        group = conn.execute(
            """
            INSERT INTO asset_card_vulnerability_groups
                (asset_id, source_type, collection_type, collection_id, group_order, updated_at)
            VALUES ('linux-test', 'docker', 'docker', 'containers', 0, 'test')
            RETURNING id
            """
        ).fetchone()
        conn.execute(
            """
            INSERT INTO asset_card_vulnerabilities (asset_id, group_id, cve_name, updated_at)
            VALUES ('linux-test', %s, %s, 'test')
            """,
            (group["id"], f" {cve.lower()} "),
        )
    assert assess_asset("linux-test", additional_only=True)["matches"] == []
    assert assess_asset("linux-test")["matches"] == result["matches"]
    assert local_asset_wazuh_cti_matches("linux-test", additional_only=True)["matches"] == []

    with db.connect() as conn:
        conn.execute("DELETE FROM wazuh_cti_package_rules WHERE passport_id = %s", (passport_id,))
        conn.execute(
            "UPDATE wazuh_asset_assessments SET checked_at = now() - interval '2 hours' WHERE asset_id = 'linux-test'"
        )
    assert local_asset_wazuh_cti_matches("linux-test")["matches"] == result["matches"]
    reconcile_due_assets(Event())
    assert local_asset_wazuh_cti_matches("linux-test")["matches"] == []

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
