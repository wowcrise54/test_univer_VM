"""Load a small deterministic demo dataset into the isolated test database."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clean", action="store_true", help="remove only records owned by this demo seed")
    args = parser.parse_args()
    database_url = os.environ.get("MPVM_DATABASE_URL", "")
    parsed_url = urlsplit(database_url)
    if (
        parsed_url.scheme != "postgresql"
        or parsed_url.hostname != "test-postgres"
        or parsed_url.port != 5432
        or parsed_url.username != "test"
        or parsed_url.password != "test"
        or parsed_url.path != "/mpvm_test"
        or parsed_url.query
        or parsed_url.fragment
    ):
        raise SystemExit("Refusing to seed: MPVM_DATABASE_URL is not the compose.test.yml database")
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT, check=True)
    sys.path.insert(0, str(ROOT))
    from app import db

    db.init_db()
    if args.clean:
        with db.connect() as conn:
            conn.execute("DELETE FROM asset_cards WHERE asset_id LIKE 'demo-%'")
            conn.execute("DELETE FROM vulnerability_passports WHERE internal_id LIKE 'demo-passport-%'")
            conn.execute("DELETE FROM operations WHERE operation_id LIKE 'demo-removal-%'")
            conn.execute("DELETE FROM asset_groups WHERE group_id = %s", (uuid.UUID("ad180c55-6f65-4a9c-b27a-e87e30000001"),))
        print("Removed demo-seed records from the isolated test database")
        return
    fixtures = ROOT / "tests" / "fixtures" / "mpvm"
    archive_samples = json.loads((fixtures / "archive_response_samples.json").read_text(encoding="utf-8"))
    linux = archive_samples["tree_root"]["body"]
    windows = json.loads((fixtures / "assets_tree_windows_root.json").read_text(encoding="utf-8"))
    vuln_response = json.loads((fixtures / "host_soft_vulnerabilities.json").read_text(encoding="utf-8"))
    passport_response = json.loads((fixtures / "passport_query_response.json").read_text(encoding="utf-8"))
    from app.mpvm.passport_records import normalize_vulnerability_passport_record

    passports = [normalize_vulnerability_passport_record(row) for row in passport_response["records"]]
    db.upsert_vulnerability_passports(passports)
    for root, level in ((linux, "Critical"), (windows, "Medium")):
        findings = [{
            "vulnerability_instance_id": item["id"],
            "vulnerability_id": item["cve"], "cve_name": item["cve"],
            "name": item["name"], "level": item["severity"],
            "cvss_score": item["cvssScore"], "object_id": root["objectId"],
            "status": item["status"], "fixed_version": item["fixedVersion"],
        } for item in vuln_response["items"]] if "Linux" in root["type"] else []
        card = {
            "asset_id": root["objectId"], "display_name": root["displayName"],
            "asset_type": root["type"], "root": root, "metadata": {},
            "nodes": [], "collections": [], "table_rows": [],
            "vulnerabilities": {"sources": [{"source": "os", "collection_type": "HostSoftVulnerabilities",
                "groups": [{"collection_id": f"demo-{root['objectId']}-software", "name": "Software findings",
                    "level": level, "vulnerabilities_count": len(findings), "cvss_score": max((f["cvss_score"] for f in findings), default=0),
                    "order": 0, "items": findings}]}]},
            "stats": {"finding_count": len(findings)},
        }
        card["vulnerability_level"] = level
        db.upsert_asset_card(card)
    group_id = uuid.UUID("ad180c55-6f65-4a9c-b27a-e87e30000001")
    group_query = {
        "combinator": "and", "match_scope": "host",
        "rules": [{"field_path": "asset.assetId", "operator": "equals", "value": linux["objectId"]}],
    }
    with db.connect() as conn:
        conn.execute(
            """INSERT INTO asset_groups (group_id, name, description, query_json, definition_version,
               status, created_by, created_at, updated_at)
               VALUES (%s, 'Demo Linux assets', 'Synthetic fixture group', %s, 1, 'stale', 'demo-seed', NOW(), NOW())
               ON CONFLICT (group_id) DO UPDATE SET query_json = EXCLUDED.query_json,
               status = 'stale', last_error = NULL, updated_at = NOW()""",
            (group_id, json.dumps(group_query)),
        )
        conn.execute("DELETE FROM asset_group_evaluations WHERE group_id = %s", (group_id,))
    db.evaluate_local_asset_group(str(group_id))
    for suffix, status, stage, progress, message, error in (
        ("done", "succeeded", "completed", 100, "Synthetic removal completed", {}),
        ("pending", "queued", "queued", 0, "Synthetic removal waiting", {}),
        ("failed", "failed", "failed", 100, "Synthetic removal failed", {"code": "DEMO_ERROR"}),
    ):
        db.register_operation(
            f"demo-removal-{suffix}", kind="asset_removal", source_id=f"demo-removal-{suffix}",
            status=status, stage=stage, progress_percent=progress, subject_type="asset",
            subject_id=linux["objectId"], subject_label=linux["displayName"], message=message,
            error=error, request={"asset_ids": [linux["objectId"]]},
            result={"operationId": f"demo-removal-{suffix}"} if status == "succeeded" else {},
        )
    with db.connect() as conn:
        counts = conn.execute(
            """SELECT
                (SELECT COUNT(*) FROM asset_cards WHERE LEFT(asset_id, 5) = 'demo-') AS cards,
                (SELECT COUNT(*) FROM vulnerability_passports WHERE LEFT(internal_id, 14) = 'demo-passport-') AS passports,
                (SELECT COUNT(*) FROM asset_card_vulnerabilities WHERE asset_id = %s) AS findings,
                (SELECT COUNT(*) FROM asset_card_vulnerability_passports link
                 JOIN asset_card_vulnerabilities finding ON finding.id = link.asset_vulnerability_id
                 WHERE finding.asset_id = %s) AS passport_links,
                (SELECT COUNT(*) FROM asset_groups WHERE group_id = %s) AS groups,
                (SELECT COUNT(*) FROM asset_group_members WHERE group_id = %s) AS group_members,
                (SELECT COUNT(*) FROM asset_group_evaluations WHERE group_id = %s AND status = 'completed') AS group_evaluations,
                (SELECT COUNT(*) FROM operations WHERE LEFT(operation_id, 13) = 'demo-removal-') AS operations,
                (SELECT COUNT(DISTINCT vulnerability_json::jsonb->>'status') FROM asset_card_vulnerabilities
                 WHERE asset_id = %s) AS finding_statuses""",
            (linux["objectId"], linux["objectId"], group_id, group_id, group_id, linux["objectId"]),
        ).fetchone()
    expected = {"cards": 2, "passports": 2, "findings": 2, "passport_links": 2, "groups": 1, "group_members": 1, "group_evaluations": 1, "operations": 3, "finding_statuses": 2}
    actual = {key: int(counts[key]) for key in expected}
    if actual != expected:
        raise RuntimeError(f"Demo seed verification failed: expected {expected}, got {actual}")
    print("Loaded 2 demo asset cards, 2 passports, 1 group, and 3 operations")


if __name__ == "__main__":
    main()
