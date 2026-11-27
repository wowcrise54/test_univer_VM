"""Generate a large, deterministic asset-card/passport workload in scale PostgreSQL."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import uuid
from itertools import islice
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
STAMP = "2026-01-01T00:00:00Z"
ASSET_GROUP_ID = uuid.UUID("ad180c55-6f65-4a9c-b27a-e87e30000002")
EVALUATION_ID = uuid.UUID("ad180c55-6f65-4a9c-b27a-e87e30000003")


def counts_for(profile: str) -> dict[str, int]:
    if profile == "small":
        return {"assets": 2, "passports": 10, "findings": 20}
    if profile == "large":
        return {"assets": 500, "passports": 500_000, "findings": 1_000_000}
    raise ValueError(f"Unknown scale profile: {profile}")


def asset_id_for(index: int, counts: dict[str, int]) -> str:
    per_asset = counts["findings"] // counts["assets"]
    if not 0 <= index < counts["findings"]:
        raise IndexError(index)
    return f"scale-demo-asset-{index // per_asset:04d}"


def passport_index_for_finding(index: int) -> int:
    if index < 0:
        raise IndexError(index)
    return index // 2


def passport_id_for(index: int) -> str:
    return f"scale-demo-passport-{index:06d}"


def finding_id_for(index: int) -> str:
    return f"scale-demo-finding-{index:07d}"


def resume_index_from_prefix(
    existing_count: int,
    first_id: str | None,
    last_id: str | None,
    total: int,
    id_for,
) -> int:
    if existing_count < 0 or existing_count > total:
        raise ValueError(f"Existing row count {existing_count} is outside expected range 0..{total}")
    if existing_count == 0:
        if first_id is not None or last_id is not None:
            raise ValueError("An empty scale table returned unexpected boundary IDs")
        return 0
    if first_id != id_for(0) or last_id != id_for(existing_count - 1):
        raise ValueError("Existing scale rows are not a contiguous deterministic prefix; run with --clean")
    return existing_count


def require_scale_database(database_url: str) -> None:
    parsed = urlsplit(database_url)
    if (
        parsed.scheme != "postgresql"
        or parsed.hostname != "scale-postgres"
        or parsed.port != 5432
        or parsed.username != "test"
        or parsed.password != "test"
        or parsed.path != "/mpvm_scale"
        or parsed.query
        or parsed.fragment
    ):
        raise SystemExit("Refusing to seed: MPVM_DATABASE_URL is not the dedicated scale-test database")


def _copy_batches(db, table: str, columns: tuple[str, ...], rows, total: int, batch_size: int = 5000) -> None:
    iterator = iter(rows)
    written = 0
    while batch := list(islice(iterator, batch_size)):
        with db.connect() as conn:
            with conn.cursor() as cursor:
                db.copy_rows(cursor, table, columns, batch)
        written += len(batch)
        print(f"{table}: {written:,}/{total:,}", flush=True)


def _asset_data(index: int, counts: dict[str, int]) -> dict:
    asset_id = f"scale-demo-asset-{index:04d}"
    if index < 254:
        ip = f"192.0.2.{index + 1}"
    else:
        ip = f"198.51.100.{index - 253}"
    is_windows = index % 5 == 4
    host = f"scale-{'win' if is_windows else 'linux'}-{index + 1:04d}"
    os_name, os_version, asset_type = (
        ("Windows Server 2022", "10.0.20348", "OperatingSystem.Windows.Server")
        if is_windows
        else (("Ubuntu Server", "24.04", "OperatingSystem.UNIX.Linux.UbuntuHost") if index % 2 == 0 else ("Debian", "12", "OperatingSystem.UNIX.Linux.DebianHost"))
    )
    level = ("Critical", "High", "Medium", "Low")[index % 4]
    finding_count = counts["findings"] // counts["assets"]
    root = {
        "displayName": host,
        "objectId": asset_id,
        "type": asset_type,
        "vulnerabilityLevel": level,
        "data": {"hostname": host, "fqdn": f"{host}.example.test", "ipAddress": ip, "osName": os_name, "osVersion": os_version},
    }
    collection_id = f"scale-demo-group-{index:04d}"
    vulnerability_group = {
        "collection_id": collection_id,
        "name": "Operating-system packages",
        "level": level.lower(),
        "vulnerabilities_count": finding_count,
        "cvss_score": 9.8,
        "order": 0,
        "truncated": False,
    }
    return {
        "asset_id": asset_id,
        "display_name": host,
        "asset_type": asset_type,
        "hostname": host,
        "fqdn": f"{host}.example.test",
        "ip_address": ip,
        "os_name": os_name,
        "os_version": os_version,
        "vulnerability_level": level,
        "root_json": json.dumps(root, separators=(",", ":")),
        "vulnerabilities_json": json.dumps({"header": {"os_soft_vulnerabilities_count": finding_count, "network_services_vulnerabilities_count": 0}, "sources": [{"source": "os", "collection_type": "HostSoftVulnerabilities", "groups": [vulnerability_group]}]}, separators=(",", ":")),
        "collection_id": collection_id,
        "finding_count": finding_count,
    }


def asset_node_row(index: int, counts: dict[str, int]) -> dict:
    asset = _asset_data(index, counts)
    root = json.loads(asset["root_json"])
    return {
        "asset_id": asset["asset_id"],
        "path": "asset",
        "title": root["displayName"],
        "display_name": root["displayName"],
        "object_id": root["objectId"],
        "type": root["type"],
        "vulnerability_level": root["vulnerabilityLevel"],
        "data": root["data"],
        "node_json": root,
    }


def _asset_rows(counts: dict[str, int]):
    for index in range(counts["assets"]):
        row = _asset_data(index, counts)
        yield (
            row["asset_id"], row["display_name"], row["asset_type"], row["fqdn"], row["hostname"],
            row["ip_address"], row["os_name"], row["os_version"], row["vulnerability_level"],
            None, None, row["root_json"], "{}", json.dumps([json.loads(row["root_json"])], separators=(",", ":")), "[]", "[]", row["vulnerabilities_json"],
            "{}", "{}", STAMP, STAMP,
        )


def _asset_node_rows(counts: dict[str, int]):
    for index in range(counts["assets"]):
        node = asset_node_row(index, counts)
        yield (
            node["asset_id"], node["path"], node["title"], node["display_name"],
            node["object_id"], node["type"], node["vulnerability_level"],
            json.dumps(node["data"], separators=(",", ":")),
            json.dumps(node["node_json"], separators=(",", ":")), STAMP,
        )


def _vulnerability_group_rows(counts: dict[str, int]):
    for index in range(counts["assets"]):
        row = _asset_data(index, counts)
        yield (
            row["asset_id"], "os", "HostSoftVulnerabilities", row["collection_id"],
            "Operating-system packages", ("critical", "high", "medium", "low")[index % 4],
            row["finding_count"], 9.8, 0, False, "{}", STAMP,
        )


def _passport_rows(counts: dict[str, int], start: int = 0):
    levels = (("Critical", 9.8), ("High", 8.1), ("Medium", 6.5), ("Low", 4.3))
    for index in range(start, counts["passports"]):
        level, score = levels[index % len(levels)]
        cve = f"CVE-2026-{index + 1_000_000:07d}"
        package = f"demo-package-{index % 250:03d}"
        version = f"{1 + (index % 9)}.{(index // 9) % 10}.0"
        yield (
            passport_id_for(index), f"scale-demo-external-{index:06d}",
            f"Synthetic package vulnerability {index + 1:06d}", level, f"{score:.1f}",
            STAMP, package, version, json.dumps([{"display_name": cve}], separators=(",", ":")),
            json.dumps({"cvss": score}, separators=(",", ":")), "{}", "scale-demo", None, STAMP, STAMP,
        )


def _finding_rows(counts: dict[str, int], group_ids: dict[str, int], start: int = 0):
    per_asset = counts["findings"] // counts["assets"]
    scores = (9.8, 8.1, 6.5, 4.3)
    levels = ("critical", "high", "medium", "low")
    for index in range(start, counts["findings"]):
        asset_index = index // per_asset
        passport_index = passport_index_for_finding(index)
        asset_id = f"scale-demo-asset-{asset_index:04d}"
        cve = f"CVE-2026-{passport_index + 1_000_000:07d}"
        fixed = index % 2 == 0
        score_index = passport_index % len(scores)
        status = "fixed" if fixed else "new"
        fixed_version = f"{2 + (passport_index % 8)}.0.1" if fixed else None
        raw = json.dumps({"status": status, "fixed_version": fixed_version, "package_name": f"demo-package-{passport_index % 250:03d}", "package_version": "1.0.0"}, separators=(",", ":"))
        yield (
            asset_id, group_ids[asset_id], finding_id_for(index), f"scale-demo-vuln-{passport_index:06d}", asset_id,
            cve, f"Synthetic vulnerability {passport_index + 1:06d}", levels[score_index], scores[score_index],
            None, raw, STAMP,
        )


def _clean(db) -> None:
    with db.connect() as conn:
        conn.execute(
            """DELETE FROM asset_card_vulnerability_passports link
               USING asset_card_vulnerabilities finding
               WHERE link.asset_vulnerability_id = finding.id AND LEFT(finding.asset_id, 11) = 'scale-demo-'"""
        )
    print("scale cleanup: finding links", flush=True)
    with db.connect() as conn:
        conn.execute("DELETE FROM asset_card_vulnerabilities WHERE LEFT(asset_id, 11) = 'scale-demo-'")
    print("scale cleanup: findings", flush=True)
    with db.connect() as conn:
        conn.execute("DELETE FROM asset_card_vulnerability_groups WHERE LEFT(asset_id, 11) = 'scale-demo-'")
        conn.execute("DELETE FROM asset_group_members WHERE group_id = %s", (ASSET_GROUP_ID,))
        conn.execute("DELETE FROM asset_group_evaluations WHERE group_id = %s", (ASSET_GROUP_ID,))
        conn.execute("DELETE FROM asset_groups WHERE group_id = %s", (ASSET_GROUP_ID,))
        conn.execute("DELETE FROM operations WHERE LEFT(operation_id, 11) = 'scale-demo-'")
    print("scale cleanup: groups and operations", flush=True)
    with db.connect() as conn:
        conn.execute(
            """DELETE FROM vulnerability_passport_cves cve USING vulnerability_passports passport
               WHERE cve.passport_internal_id = passport.internal_id AND LEFT(passport.internal_id, 11) = 'scale-demo-'"""
        )
        conn.execute(
            """DELETE FROM vulnerability_passport_os_family family USING vulnerability_passports passport
               WHERE family.passport_internal_id = passport.internal_id AND LEFT(passport.internal_id, 11) = 'scale-demo-'"""
        )
    print("scale cleanup: passport match indexes", flush=True)
    with db.connect() as conn:
        conn.execute("DELETE FROM vulnerability_passports WHERE LEFT(internal_id, 11) = 'scale-demo-'")
    print("scale cleanup: passports", flush=True)
    with db.connect() as conn:
        conn.execute("DELETE FROM asset_cards WHERE LEFT(asset_id, 11) = 'scale-demo-'")
    print("scale cleanup: cards", flush=True)


def _count_scale_rows(db, table: str, column: str) -> int:
    with db.connect() as conn:
        return int(conn.execute(
            f"SELECT COUNT(*) AS count FROM {table} WHERE LEFT({column}, 11) = 'scale-demo-'"
        ).fetchone()["count"])


def _resume_prefix(db, table: str, column: str, total: int, id_for) -> int:
    with db.connect() as conn:
        row = conn.execute(
            f"""SELECT COUNT(*) AS count, MIN({column}) AS first_id, MAX({column}) AS last_id
                FROM {table} WHERE LEFT({column}, 11) = 'scale-demo-'"""
        ).fetchone()
    return resume_index_from_prefix(int(row["count"]), row["first_id"], row["last_id"], total, id_for)


def _resume_finding_prefix(db, total: int) -> int:
    with db.connect() as conn:
        row = conn.execute(
            """SELECT COUNT(*) AS count, MIN(vulnerability_instance_id) AS first_id,
                      MAX(vulnerability_instance_id) AS last_id
               FROM asset_card_vulnerabilities WHERE LEFT(asset_id, 11) = 'scale-demo-'"""
        ).fetchone()
    return resume_index_from_prefix(int(row["count"]), row["first_id"], row["last_id"], total, finding_id_for)


def _create_scale_group(db, counts: dict[str, int]) -> None:
    now = STAMP
    query = {"combinator": "and", "match_scope": "host", "rules": [{"field_path": "asset.hostname", "operator": "starts_with", "value": "scale-"}]}
    with db.connect() as conn:
        conn.execute(
            """INSERT INTO asset_groups (group_id, name, description, query_json, definition_version,
                status, member_count, indexed_cards, total_cards, last_evaluated_at, created_by, created_at, updated_at)
                VALUES (%s, 'Scale test assets', 'Synthetic high-volume fixture group', %s, 1,
                'ready', %s, %s, %s, %s, 'scale-seed', %s, %s)
                ON CONFLICT (group_id) DO UPDATE SET query_json=EXCLUDED.query_json, status='ready',
                member_count=EXCLUDED.member_count, indexed_cards=EXCLUDED.indexed_cards,
                total_cards=EXCLUDED.total_cards, last_evaluated_at=EXCLUDED.last_evaluated_at,
                updated_at=EXCLUDED.updated_at""",
            (ASSET_GROUP_ID, json.dumps(query), counts["assets"], counts["assets"], counts["assets"], now, now, now),
        )
        conn.execute("DELETE FROM asset_group_evaluations WHERE group_id = %s", (ASSET_GROUP_ID,))
        conn.execute(
            """INSERT INTO asset_group_evaluations (evaluation_id, group_id, definition_version, status,
                matched_count, indexed_cards, total_cards, started_at, finished_at)
                VALUES (%s, %s, 1, 'completed', %s, %s, %s, %s, %s)""",
            (EVALUATION_ID, ASSET_GROUP_ID, counts["assets"], counts["assets"], counts["assets"], now, now),
        )
        conn.execute(
            """INSERT INTO asset_group_members (group_id, asset_id, evaluation_id, membership_source, evidence_json, evaluated_at)
                SELECT %s, asset_id, %s, 'rule', '[]', %s FROM asset_cards
                WHERE LEFT(asset_id, 11) = 'scale-demo-'
                ON CONFLICT (group_id, asset_id) DO UPDATE SET evaluation_id=EXCLUDED.evaluation_id,
                membership_source=EXCLUDED.membership_source, evidence_json=EXCLUDED.evidence_json,
                evaluated_at=EXCLUDED.evaluated_at""",
            (ASSET_GROUP_ID, EVALUATION_ID, now),
        )
    for suffix, status, stage, progress in (
        ("done", "succeeded", "completed", 100),
        ("pending", "queued", "queued", 0),
        ("failed", "failed", "failed", 100),
    ):
        operation_id = f"scale-demo-{suffix}"
        db.register_operation(
            operation_id, kind="asset_removal", source_id=operation_id,
            status=status, stage=stage, progress_percent=progress,
            subject_type="asset", subject_id="scale-demo-asset-0000",
            subject_label="scale-linux-0001", message=f"Synthetic scale removal {suffix}",
            error={"code": "SCALE_DEMO_ERROR"} if status == "failed" else {},
            request={"asset_ids": ["scale-demo-asset-0000"]},
            result={"operationId": operation_id} if status == "succeeded" else {},
            created_at=STAMP, started_at=STAMP if status != "queued" else None,
            finished_at=STAMP if status in {"succeeded", "failed"} else None, updated_at=STAMP,
        )


def _verify(db, counts: dict[str, int]) -> None:
    per_asset = counts["findings"] // counts["assets"]
    with db.connect() as conn:
        actual = conn.execute(
            """SELECT
                (SELECT COUNT(*) FROM asset_cards WHERE LEFT(asset_id, 11)='scale-demo-') AS assets,
                (SELECT COUNT(*) FROM asset_card_nodes WHERE LEFT(asset_id, 11)='scale-demo-' AND path='asset') AS asset_nodes,
                (SELECT COUNT(*) FROM vulnerability_passports WHERE LEFT(internal_id, 11)='scale-demo-') AS passports,
                (SELECT COUNT(*) FROM asset_card_vulnerabilities WHERE LEFT(asset_id, 11)='scale-demo-') AS findings,
                (SELECT COUNT(*) FROM asset_card_vulnerability_passports link
                 JOIN asset_card_vulnerabilities finding ON finding.id=link.asset_vulnerability_id
                 WHERE LEFT(finding.asset_id, 11)='scale-demo-') AS links,
                (SELECT COUNT(*) FROM asset_group_members WHERE group_id=%s) AS group_members,
                (SELECT COUNT(*) FROM operations WHERE LEFT(operation_id, 11)='scale-demo-') AS operations,
                (SELECT COUNT(DISTINCT vulnerability_json::jsonb->>'status') FROM asset_card_vulnerabilities
                 WHERE LEFT(asset_id, 11)='scale-demo-') AS statuses""",
            (ASSET_GROUP_ID,),
        ).fetchone()
    expected = {"assets": counts["assets"], "asset_nodes": counts["assets"], "passports": counts["passports"], "findings": counts["findings"], "links": counts["findings"], "group_members": counts["assets"], "operations": 3, "statuses": 2}
    found = {key: int(actual[key]) for key in expected}
    if found != expected:
        raise RuntimeError(f"Scale seed verification failed: expected {expected}, got {found}; findings per card={per_asset}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=("small", "large"), default="large")
    parser.add_argument("--clean", action="store_true", help="remove only scale-demo records")
    args = parser.parse_args()
    require_scale_database(os.environ.get("MPVM_DATABASE_URL", ""))
    counts = counts_for(args.profile)
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT, check=True)
    sys.path.insert(0, str(ROOT))
    from app import db

    db.init_db()
    if args.clean:
        _clean(db)
        print("Removed scale-demo records from dedicated scale-test database")
        return

    asset_count = _count_scale_rows(db, "asset_cards", "asset_id")
    if asset_count not in (0, counts["assets"]):
        raise ValueError(f"Found {asset_count} scale assets; run --clean before changing profiles")
    if asset_count == 0:
        _copy_batches(
            db, "asset_cards",
            ("asset_id", "display_name", "asset_type", "fqdn", "hostname", "ip_address", "os_name", "os_version", "vulnerability_level", "token_timestamp", "asset_token", "root_json", "metadata_json", "nodes_json", "collections_json", "table_rows_json", "vulnerabilities_json", "stats_json", "raw_card_json", "first_seen", "last_seen"),
            _asset_rows(counts), counts["assets"],
        )
    else:
        print(f"asset_cards: resuming with {asset_count:,}/{counts['assets']:,} already present", flush=True)
    node_count = _count_scale_rows(db, "asset_card_nodes", "asset_id")
    if node_count == 0:
        _copy_batches(
            db, "asset_card_nodes",
            ("asset_id", "path", "title", "display_name", "object_id", "object_type", "vulnerability_level", "data_json", "node_json", "updated_at"),
            _asset_node_rows(counts), counts["assets"],
        )
    elif node_count != counts["assets"]:
        raise ValueError(f"Found {node_count} scale asset nodes; run --clean to repair them")
    else:
        print(f"asset_card_nodes: {node_count:,}/{counts['assets']:,} already present", flush=True)
    with db.connect() as conn:
        for index in range(counts["assets"]):
            asset = _asset_data(index, counts)
            db.replace_asset_card_search_index(conn, asset["asset_id"], asset, STAMP)
    group_count = _count_scale_rows(db, "asset_card_vulnerability_groups", "asset_id")
    if group_count not in (0, counts["assets"]):
        raise ValueError(f"Found {group_count} scale vulnerability groups; run --clean to repair them")
    if group_count == 0:
        _copy_batches(
            db, "asset_card_vulnerability_groups",
            ("asset_id", "source_type", "collection_type", "collection_id", "name", "severity", "vulnerability_count", "cvss_score", "group_order", "truncated", "group_json", "updated_at"),
            _vulnerability_group_rows(counts), counts["assets"],
        )
    else:
        print(f"asset_card_vulnerability_groups: {group_count:,}/{counts['assets']:,} already present", flush=True)
    with db.connect() as conn:
        group_ids = {row["asset_id"]: int(row["id"]) for row in conn.execute("SELECT id, asset_id FROM asset_card_vulnerability_groups WHERE LEFT(asset_id, 11)='scale-demo-'").fetchall()}
    passport_start = _resume_prefix(db, "vulnerability_passports", "internal_id", counts["passports"], passport_id_for)
    if passport_start < counts["passports"]:
        _copy_batches(
            db, "vulnerability_passports",
            ("internal_id", "external_id", "name", "severity", "score", "issue_time", "package_id", "package_version", "cves_json", "metrics_json", "raw_record_json", "source_pdql", "pdql_token", "first_seen", "last_seen"),
            _passport_rows(counts, passport_start), counts["passports"] - passport_start,
        )
    else:
        print(f"vulnerability_passports: {passport_start:,}/{counts['passports']:,} already present", flush=True)

    finding_start = _resume_finding_prefix(db, counts["findings"])
    if finding_start < counts["findings"]:
        _copy_batches(
            db, "asset_card_vulnerabilities",
            ("asset_id", "group_id", "vulnerability_instance_id", "vulnerability_id", "object_id", "cve_name", "name", "severity", "cvss_score", "description_key", "vulnerability_json", "updated_at"),
            _finding_rows(counts, group_ids, finding_start), counts["findings"] - finding_start, batch_size=10_000,
        )
    else:
        print(f"asset_card_vulnerabilities: {finding_start:,}/{counts['findings']:,} already present", flush=True)

    with db.connect() as conn:
        conn.execute("ANALYZE asset_card_vulnerabilities")
        conn.execute("ANALYZE vulnerability_passport_cves")
        conn.execute("ANALYZE vulnerability_passports")
    with db.connect() as conn:
        link_count = int(conn.execute(
            """SELECT COUNT(*) AS count FROM asset_card_vulnerability_passports link
               JOIN asset_card_vulnerabilities finding ON finding.id=link.asset_vulnerability_id
               WHERE LEFT(finding.asset_id,11)='scale-demo-'"""
        ).fetchone()["count"])
        if link_count < counts["findings"]:
            conn.execute("SET LOCAL work_mem = '128MB'")
            conn.execute(
                """INSERT INTO asset_card_vulnerability_passports (asset_vulnerability_id, passport_internal_id, match_method, linked_at)
                SELECT finding.id, passport.internal_id, 'cve', %s
                FROM asset_card_vulnerabilities finding
                JOIN vulnerability_passport_cves passport_cve ON passport_cve.cve_name = UPPER(finding.cve_name)
                JOIN vulnerability_passports passport ON passport.internal_id = passport_cve.passport_internal_id
                WHERE LEFT(finding.asset_id, 11) = 'scale-demo-'
                ON CONFLICT (asset_vulnerability_id, passport_internal_id) DO NOTHING""",
                (STAMP,),
            )
        elif link_count > counts["findings"]:
            raise ValueError(f"Found {link_count} scale passport links; run --clean to repair them")
    _create_scale_group(db, counts)
    _verify(db, counts)
    print(f"Scale demo seed verified: {counts['assets']:,} assets, {counts['passports']:,} passports, {counts['findings']:,} findings")


if __name__ == "__main__":
    main()
