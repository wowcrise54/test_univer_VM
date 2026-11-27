import json
import re
from pathlib import Path

import pytest

from app.mpvm.passport_records import normalize_vulnerability_passport_record
from app.mpvm_client import MpVmApiError

FIXTURES = Path(__file__).parent / "fixtures" / "mpvm"


def test_archive_response_samples_keep_mpvm_shapes_and_synthetic_identity():
    examples = json.loads((FIXTURES / "archive_response_samples.json").read_text(encoding="utf-8"))
    root = examples["tree_root"]["body"]
    assert examples["tree_root"]["status"] == 200
    assert {"displayName", "objectId", "type", "vulnerabilityLevel", "data"} <= root.keys()
    assert root["data"]["hostname"] == "demo-linux-01"
    assert root["data"]["ipAddress"] == "192.0.2.11"
    vulnerability_group = examples["host_soft_vulnerabilities"]["body"]
    assert examples["host_soft_vulnerabilities"]["status"] == 200
    assert {"level", "vulnerabilitiesCount", "cvssScore", "items"} <= vulnerability_group.keys()
    assert vulnerability_group["items"]
    assert {item["status"] for item in json.loads((FIXTURES / "host_soft_vulnerabilities.json").read_text(encoding="utf-8"))["items"]} == {"fixed", "new"}


def test_removal_fixtures_cover_completed_pending_and_empty_responses():
    outcomes = json.loads((FIXTURES / "asset_removal_responses.json").read_text(encoding="utf-8"))
    assert outcomes["completed"]["status"] == 201
    assert outcomes["completed"]["body"]["operationId"].startswith("demo-")
    assert outcomes["pending"] == {"status": 202, "body": None}
    assert outcomes["empty"] == {"status": 204, "body": None}


def test_archive_group_and_removal_shapes_are_retained_after_anonymization():
    samples = json.loads((FIXTURES / "archive_response_samples.json").read_text(encoding="utf-8"))
    groups = samples["group_hierarchy"]
    assert groups["status"] == 200
    assert isinstance(groups["body"], list)
    assert {"id", "name", "children"} <= groups["body"][0].keys()
    flat = []

    def visit(nodes):
        for node in nodes:
            flat.append(node)
            visit(node.get("children") or [])

    visit(groups["body"])
    assert len({node["id"] for node in flat}) == len(flat)
    assert all(node["name"].startswith("Demo group") for node in flat)
    removal = samples["asset_removal"]
    assert removal["status"] == 201
    assert removal["body"]["operationId"].startswith("demo-")


def test_synthetic_passport_query_response_normalizes_to_seed_records():
    response = json.loads((FIXTURES / "passport_query_response.json").read_text(encoding="utf-8"))
    passports = [normalize_vulnerability_passport_record(row) for row in response["records"]]
    assert [row["internal_id"] for row in passports] == ["demo-passport-001", "demo-passport-002"]
    assert passports[0]["cves"][0]["display_name"].startswith("CVE-2026-")
    assert passports[0]["package_version"] == "1.0.0"
    assert "assets_grid/data" in response["fixture_kind"]
    findings = json.loads((FIXTURES / "host_soft_vulnerabilities.json").read_text(encoding="utf-8"))["items"]
    passport_cves = {cve["display_name"] for passport in passports for cve in passport["cves"]}
    assert {finding["cve"] for finding in findings} <= passport_cves


def test_fixture_corpus_contains_no_environment_urls_or_credentials():
    for path in FIXTURES.glob("*.json"):
        content = path.read_text(encoding="utf-8").lower()
        assert "utmn.ru" not in content
        assert "srv-sc-watcher" not in content
        assert "authorization" not in content
        assert "cookie" not in content
        assert "client_secret" not in content
        assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", content)


def test_mpvm_client_accepts_archive_root_response_shape(monkeypatch):
    from app import mpvm_client

    payload = json.loads((FIXTURES / "archive_response_samples.json").read_text(encoding="utf-8"))["tree_root"]["body"]
    client = object.__new__(mpvm_client.MpVmClient)
    client.auth = type("Auth", (), {"api_url": "https://fixture.invalid", "timeout": 1})()
    client.session = type("Session", (), {"get": lambda *_args, **_kwargs: type("Response", (), {
        "ok": True, "json": lambda _self: payload,
    })()})()
    result = client.get_asset_tree_root("synthetic-token", "synthetic-timeline")
    assert result["data"]["hostname"] == "demo-linux-01"


@pytest.mark.parametrize("payload", [[], None, "not-json"])
def test_mpvm_client_rejects_empty_or_incomplete_root_response(payload):
    from app import mpvm_client

    class Response:
        ok = True

        def json(self):
            if payload == "not-json":
                raise ValueError("invalid JSON")
            return payload

    class Session:
        def get(self, *_args, **_kwargs):
            return Response()

    client = object.__new__(mpvm_client.MpVmClient)
    client.auth = type("Auth", (), {"api_url": "https://fixture.invalid", "timeout": 1})()
    client.session = Session()
    with pytest.raises(MpVmApiError):
        client.get_asset_tree_root("synthetic-token", "synthetic-timeline")


def test_mpvm_client_rejects_http_failure_for_root_response():
    from app import mpvm_client

    class Response:
        ok = False
        status_code = 503
        text = "synthetic upstream failure"
        headers = {}

        def json(self):
            raise ValueError("non-JSON error body")

    class Session:
        def get(self, *_args, **_kwargs):
            return Response()

    client = object.__new__(mpvm_client.MpVmClient)
    client.auth = type("Auth", (), {"api_url": "https://fixture.invalid", "timeout": 1})()
    client.session = Session()
    with pytest.raises(MpVmApiError, match="503"):
        client.get_asset_tree_root("synthetic-token", "synthetic-timeline")
