from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from .. import db
from ..domain.compliance import (
    ComplianceScope,
    classify_asset_type,
    evaluate_freshness,
    is_internet_asset,
)


@dataclass(frozen=True)
class ComplianceDataset:
    scope: ComplianceScope
    assessment_date: date
    generated_at: datetime
    summary: dict[str, Any]
    findings: tuple[dict[str, Any], ...]
    assets: tuple[dict[str, Any], ...]
    stale_assets: tuple[dict[str, Any], ...]
    diagnostics: dict[str, int]


def _in_scope(row: dict[str, Any], scope: ComplianceScope) -> bool:
    external = is_internet_asset(row.get("ip_address"))
    return external if scope == "internet" else not external


def _asset_row(row: dict[str, Any], assessment_date: date) -> dict[str, Any]:
    primary_scan = row.get("scanned_at")
    scan_at = primary_scan or row.get("card_last_seen")
    freshness = evaluate_freshness(scan_at, assessment_date)
    return {
        "asset_id": row.get("asset_id"),
        "display_name": row.get("display_name"),
        "ip_address": row.get("ip_address"),
        "fqdn": row.get("fqdn"),
        "hostname": row.get("hostname"),
        "asset_type": row.get("asset_type"),
        "asset_category": classify_asset_type(row.get("asset_type")),
        "scan_at": freshness.scan_at.isoformat() if freshness.scan_at else None,
        "scan_date_source": "scan_completed" if primary_scan else "asset_card_last_seen",
        "is_fresh": freshness.is_fresh,
        "age_days": freshness.age_days,
        "freshness_reason": freshness.reason,
    }


def build_compliance_dataset(
    rows: Iterable[dict[str, Any]],
    *,
    scope: ComplianceScope,
    assessment_date: date,
) -> ComplianceDataset:
    scoped = [dict(row) for row in rows if _in_scope(dict(row), scope)]
    assets_by_id: dict[str, dict[str, Any]] = {}
    invalid_ip_count = 0
    for row in scoped:
        asset_id = str(row.get("asset_id") or "")
        if not asset_id:
            continue
        if not row.get("ip_address"):
            invalid_ip_count += 1
        assets_by_id.setdefault(asset_id, _asset_row(row, assessment_date))

    assets = tuple(sorted(assets_by_id.values(), key=lambda item: str(item["asset_id"])))
    stale_assets = tuple(asset for asset in assets if not asset["is_fresh"])
    findings: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, str, str]] = set()
    for row in scoped:
        asset = assets_by_id.get(str(row.get("asset_id") or ""))
        if not asset or not asset["is_fresh"]:
            continue
        if str(row.get("severity") or "").strip().lower() != "critical":
            continue
        identity = str(
            row.get("vulnerability_id")
            or row.get("cve")
            or row.get("vulnerability_name")
            or ""
        ).strip()
        if not identity:
            continue
        key = (str(asset["asset_id"]), identity, str(row.get("source_type") or ""))
        if key in seen_findings:
            continue
        seen_findings.add(key)
        findings.append(
            {
                **asset,
                "vulnerability_id": row.get("vulnerability_id"),
                "cve": row.get("cve"),
                "vulnerability_name": row.get("vulnerability_name"),
                "severity": "critical",
                "cvss_score": row.get("cvss_score"),
                "source_type": row.get("source_type"),
            }
        )
    findings.sort(key=lambda item: (str(item["asset_id"]), str(item.get("cve") or item.get("vulnerability_id") or "")))

    categories = {"user_device": 0, "server": 0, "unclassified": 0}
    for asset in assets:
        categories[asset["asset_category"]] += 1
    fresh_assets = [asset for asset in assets if asset["is_fresh"]]
    summary = {
        "scope": scope,
        "assessment_date": assessment_date.isoformat(),
        "freshness_days": 30,
        "assets_total": len(assets),
        "fresh_assets": len(fresh_assets),
        "stale_assets": len(stale_assets),
        "affected_assets": len({row["asset_id"] for row in findings}),
        "critical_findings": len(findings),
        "unique_vulnerabilities": len(
            {row.get("cve") or row.get("vulnerability_id") or row.get("vulnerability_name") for row in findings}
        ),
        "oldest_fresh_scan_at": min((asset["scan_at"] for asset in fresh_assets), default=None),
        "freshest_scan_at": max((asset["scan_at"] for asset in fresh_assets), default=None),
        "by_asset_category": categories,
    }
    return ComplianceDataset(
        scope=scope,
        assessment_date=assessment_date,
        generated_at=datetime.now(UTC),
        summary=summary,
        findings=tuple(findings),
        assets=assets,
        stale_assets=stale_assets,
        diagnostics={"invalid_or_missing_ip": invalid_ip_count},
    )


class ComplianceRepository:
    _SORT_FIELDS = {
        "asset_id",
        "display_name",
        "ip_address",
        "asset_type",
        "scan_at",
        "age_days",
        "cve",
        "cvss_score",
    }

    def _rows(self, asset_ids: list[str] | None = None) -> list[dict[str, Any]]:
        db.init_db()
        selected = list(dict.fromkeys(asset_ids or [])) or None
        with db.connect() as conn:
            rows = conn.execute(
                """
                SELECT card.asset_id, card.display_name, card.ip_address, card.fqdn,
                       card.hostname, card.asset_type, card.last_seen AS card_last_seen,
                       evidence.scanned_at,
                       finding.vulnerability_id, finding.cve_name AS cve,
                       finding.name AS vulnerability_name,
                       LOWER(TRIM(COALESCE(finding.severity, ''))) AS severity,
                       finding.cvss_score, vulnerability_group.source_type
                FROM asset_cards AS card
                LEFT JOIN asset_scan_evidence AS evidence ON evidence.asset_id = card.asset_id
                LEFT JOIN asset_card_vulnerability_groups AS vulnerability_group
                    ON vulnerability_group.asset_id = card.asset_id
                LEFT JOIN asset_card_vulnerabilities AS finding
                    ON finding.group_id = vulnerability_group.id
                WHERE (%s::text[] IS NULL OR card.asset_id = ANY(%s))
                ORDER BY card.asset_id, finding.id
                """,
                (selected, selected),
            ).fetchall()
        return [dict(row) for row in rows]

    def dataset(
        self,
        *,
        scope: ComplianceScope,
        assessment_date: date,
        asset_ids: list[str] | None = None,
    ) -> ComplianceDataset:
        return build_compliance_dataset(
            self._rows(asset_ids), scope=scope, assessment_date=assessment_date
        )

    def summary(self, *, scope: ComplianceScope, assessment_date: date) -> dict[str, Any]:
        return self.dataset(scope=scope, assessment_date=assessment_date).summary

    def _page(self, rows, *, limit, offset, sort_by, sort_dir):
        if sort_by not in self._SORT_FIELDS:
            raise ValueError(f"Unsupported sort field: {sort_by}")
        if sort_dir not in {"asc", "desc"}:
            raise ValueError("sort_dir must be asc or desc")
        ordered = sorted(
            rows,
            key=lambda item: (item.get(sort_by) is None, item.get(sort_by)),
            reverse=sort_dir == "desc",
        )
        return {"rows": list(ordered[offset : offset + limit]), "total": len(ordered)}

    def findings(self, *, scope, assessment_date, limit=50, offset=0, sort_by="cvss_score", sort_dir="desc"):
        dataset = self.dataset(scope=scope, assessment_date=assessment_date)
        return self._page(dataset.findings, limit=limit, offset=offset, sort_by=sort_by, sort_dir=sort_dir)

    def stale_assets(self, *, scope, assessment_date, limit=50, offset=0, sort_by="age_days", sort_dir="desc"):
        dataset = self.dataset(scope=scope, assessment_date=assessment_date)
        return self._page(dataset.stale_assets, limit=limit, offset=offset, sort_by=sort_by, sort_dir=sort_dir)
