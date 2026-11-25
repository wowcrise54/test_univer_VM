import pytest
from fastapi import HTTPException

from app import db
from app.repositories.passports.wazuh_cti import create_passports
from app.services import wazuh_cti

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
        }},
    }

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return document

    monkeypatch.setattr(wazuh_cti.requests, "get", lambda *args, **kwargs: Response())
    saved = wazuh_cti.refresh_passport(passport_id)
    assert saved["raw_detail"]["record"] == document
    assert saved["raw_detail"]["description"] == "Test description."
    assert saved["score"] == "9.1"

    def unavailable(*args, **kwargs):
        raise wazuh_cti.requests.Timeout

    monkeypatch.setattr(wazuh_cti.requests, "get", unavailable)
    with pytest.raises(HTTPException) as error:
        wazuh_cti.refresh_passport(passport_id)
    assert error.value.status_code == 502
    assert db.get_vulnerability_passport(passport_id)["raw_detail"]["record"] == document
