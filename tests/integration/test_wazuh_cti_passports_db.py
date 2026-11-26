import json

import pytest
from fastapi import HTTPException

from app import db
from app.repositories.passports.wazuh_cti import create_passports
from app.services import wazuh_cti
from app.services.wazuh_asset_match import assess_asset

pytestmark = pytest.mark.integration


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
