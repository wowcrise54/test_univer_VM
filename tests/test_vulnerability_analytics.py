from __future__ import annotations

import re
import unittest
from decimal import Decimal
from unittest.mock import Mock, patch

from app import main
from app.repositories.vulnerabilities import (
    VulnerabilityAnalyticsRepository,
    _filtered_findings_cte,
)
from app.services.vulnerabilities import VulnerabilityAnalyticsService


class FakeResult:
    def __init__(self, rows):
        self.rows = list(rows)

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, responses):
        self.responses = list(responses)
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=None):
        self.queries.append((sql, list(params or [])))
        return FakeResult(self.responses.pop(0))


class VulnerabilityQueryContractTests(unittest.TestCase):
    def test_trending_service_forwards_context_to_repository(self):
        repository = Mock()
        repository.trending.return_value = {
            "rows": [],
            "total": 0,
            "limit": 20,
            "context": "docker",
        }
        service = VulnerabilityAnalyticsService(repository)

        result = service.trending(limit=20, context="docker")

        repository.trending.assert_called_once_with(limit=20, context="docker")
        self.assertEqual(result["context"], "docker")

    def test_selector_precedence_and_filters_are_expressed_in_sql(self):
        sql, params = _filtered_findings_cte(
            q="CVE-2026",
            host_q="server-01",
            severity="none",
            source="software",
            selector="cve:CVE-2026-1",
        )

        self.assertLess(sql.index("finding.vulnerability_id"), sql.index("finding.cve_name"))
        self.assertIn("REGEXP_REPLACE", sql)
        self.assertIn("THEN '|source:docker' ELSE '' END", sql)
        self.assertIn("AS container_name", sql)
        self.assertIn("AS image_name", sql)
        self.assertIn("vulnerability_group.source_type = %s", sql)
        self.assertIn("= %s", sql)
        self.assertEqual(params[-3:], ["unknown", "software", "cve:CVE-2026-1"])

    def test_os_and_asset_type_filters_are_expressed_in_sql(self):
        sql, params = _filtered_findings_cte(os="Windows", asset_type="host")

        self.assertIn("(card.os_name ILIKE %s OR card.os_version ILIKE %s)", sql)
        self.assertIn("card.asset_type ILIKE %s", sql)
        self.assertEqual(params, ["%Windows%", "%Windows%", "%host%"])

    def test_asset_id_filter_is_exact_and_parameterized(self):
        sql, params = _filtered_findings_cte(asset_id="10.104.103.5")

        self.assertIn("card.asset_id = %s", sql)
        self.assertEqual(params, ["10.104.103.5"])

    def test_has_fix_filter_builds_passport_lookup_in_where(self):
        sql_yes, params_yes = _filtered_findings_cte(has_fix="yes", fix_q="обновить")
        sql_no, params_no = _filtered_findings_cte(has_fix="no")
        sql_any, params_any = _filtered_findings_cte(has_fix="any")

        for sql, _params in ((sql_yes, params_yes), (sql_no, params_no)):
            self.assertIn("asset_card_vulnerability_passports AS fix_link", sql)
            self.assertIn("vulnerability_passports AS fix_passport", sql)
            self.assertIn("raw_detail_json::jsonb -> 'howToFix'", sql)
            self.assertIn("#>> '{solution,text}'", sql)
        self.assertNotIn("NOT EXISTS", sql_yes)
        self.assertIn("NOT EXISTS", sql_no)
        self.assertNotIn("fix_link", sql_any)
        self.assertEqual(params_yes, ["%обновить%"])
        self.assertEqual(params_no, [])
        self.assertEqual(params_any, [])

    def test_invalid_has_fix_filter_is_rejected_before_querying(self):
        with self.assertRaisesRegex(ValueError, "Unsupported has_fix filter"):
            _filtered_findings_cte(has_fix="maybe")

    def test_has_fix_filter_is_expressed_without_detail_columns(self):
        full_sql, full_params = _filtered_findings_cte(has_fix="yes", fix_q="патч")
        count_sql, count_params = _filtered_findings_cte(
            has_fix="yes", fix_q="патч", include_details=False
        )

        self.assertEqual(count_params, full_params)
        self.assertEqual(count_sql.split("WHERE", 1)[1], full_sql.split("WHERE", 1)[1])
        self.assertIn("fix_link", count_sql)

    def test_list_exposes_how_to_fix_and_has_fix_from_passports(self):
        connection = FakeConnection(
            [
                [{"count": 1}],
                [
                    {
                        "selector": "cve:CVE-2026-1",
                        "vulnerability_id": None,
                        "cve": "CVE-2026-1",
                        "name": "Example vulnerability",
                        "severity": "high",
                        "cvss_score": Decimal("8.1"),
                        "affected_hosts": 2,
                        "findings": 3,
                        "affected_objects": 2,
                        "components": [],
                        "sources": ["software"],
                        "docker_containers": [],
                        "docker_images": [],
                        "passports": [],
                        "last_seen": "2026-07-11T08:00:00+00:00",
                    }
                ],
                [
                    {
                        "selector": "cve:CVE-2026-1",
                        "how_to_fix": "Обновить OpenSSL до версии 3.0.14",
                    }
                ],
            ]
        )
        repository = VulnerabilityAnalyticsRepository()
        with (
            patch("app.repositories.vulnerabilities.db.init_db"),
            patch("app.repositories.vulnerabilities.db.connect", return_value=connection),
        ):
            result = repository.list(limit=50)

        row = result["rows"][0]
        self.assertEqual(row["how_to_fix"], "Обновить OpenSSL до версии 3.0.14")
        self.assertTrue(row["has_fix"])
        # the fix text arrives via a separate bounded lookup, not the page query
        self.assertNotIn("how_to_fix", connection.queries[1][0])
        fix_sql, fix_params = connection.queries[2]
        self.assertIn("asset_card_vulnerability_passports", fix_sql)
        self.assertIn("IN (", fix_sql)
        self.assertEqual(fix_params, ["cve:CVE-2026-1"])

    def test_list_sorting_by_fix_columns_uses_filtered_fix_rollup(self):
        connection = FakeConnection(
            [
                [{"count": 1}],
                [
                    {
                        "selector": "cve:CVE-2026-1",
                        "vulnerability_id": None,
                        "cve": "CVE-2026-1",
                        "name": "Example vulnerability",
                        "severity": "high",
                        "cvss_score": Decimal("8.1"),
                        "affected_hosts": 2,
                        "findings": 3,
                        "affected_objects": 2,
                        "components": [],
                        "sources": ["software"],
                        "docker_containers": [],
                        "docker_images": [],
                        "how_to_fix": "Обновить OpenSSL",
                        "passports": [],
                        "last_seen": "2026-07-11T08:00:00+00:00",
                    }
                ],
            ]
        )
        repository = VulnerabilityAnalyticsRepository()
        with (
            patch("app.repositories.vulnerabilities.db.init_db"),
            patch("app.repositories.vulnerabilities.db.connect", return_value=connection),
        ):
            result = repository.list(sort_by="how_to_fix", sort_dir="asc", limit=50)

        row = result["rows"][0]
        self.assertEqual(row["how_to_fix"], "Обновить OpenSSL")
        self.assertTrue(row["has_fix"])
        main_sql = " ".join(connection.queries[1][0].split())
        self.assertIn("fix_rollup AS", main_sql)
        self.assertIn("fix_joined AS", main_sql)
        self.assertIn("SELECT DISTINCT selector FROM filtered_findings", main_sql)
        self.assertLess(
            main_sql.index("fix_rollup AS"), main_sql.index("asset_card_vulnerability_passports")
        )
        # no bounded follow-up query when the sort already joined the fix text
        self.assertEqual(len(connection.queries), 2)

    def test_list_without_fix_decodes_empty_columns(self):
        connection = FakeConnection(
            [
                [{"count": 1}],
                [
                    {
                        "selector": "cve:CVE-2026-2",
                        "vulnerability_id": None,
                        "cve": "CVE-2026-2",
                        "name": "Unmapped vulnerability",
                        "severity": "unknown",
                        "cvss_score": None,
                        "affected_hosts": 1,
                        "findings": 1,
                        "affected_objects": 1,
                        "components": [],
                        "sources": ["os"],
                        "docker_containers": [],
                        "docker_images": [],
                        "passports": [],
                        "last_seen": "2026-07-11T08:00:00+00:00",
                    }
                ],
                [],
            ]
        )
        repository = VulnerabilityAnalyticsRepository()
        with (
            patch("app.repositories.vulnerabilities.db.init_db"),
            patch("app.repositories.vulnerabilities.db.connect", return_value=connection),
        ):
            result = repository.list(limit=50)

        row = result["rows"][0]
        self.assertIsNone(row["how_to_fix"])
        self.assertFalse(row["has_fix"])

    def test_summary_top_vulnerabilities_fetch_fix_texts_bounded(self):
        connection = FakeConnection(
            [
                [
                    {
                        "cards_total": 1,
                        "cards_with_findings": 1,
                        "truncated_groups": 0,
                        "oldest_at": "2026-07-10T08:00:00+00:00",
                        "freshest_at": "2026-07-11T08:00:00+00:00",
                    }
                ],
                [
                    {
                        "affected_hosts": 1,
                        "findings": 1,
                        "unique_vulnerabilities": 1,
                        "unique_cves": 1,
                        "high_risk_hosts": 0,
                        "unrated_vulnerabilities": 0,
                    }
                ],
                [],
                [
                    {
                        "selector": "cve:CVE-1",
                        "vulnerability_id": None,
                        "cve": "CVE-1",
                        "name": "Example vulnerability",
                        "severity": "high",
                        "cvss_score": Decimal("8.1"),
                        "affected_hosts": 1,
                        "findings": 1,
                        "affected_objects": 1,
                        "components": [],
                        "sources": ["software"],
                        "docker_containers": [],
                        "docker_images": [],
                        "passports": [],
                        "last_seen": "2026-07-11T08:00:00+00:00",
                    }
                ],
                [
                    {
                        "selector": "cve:CVE-1",
                        "how_to_fix": "Установить патч",
                    }
                ],
                [],
            ]
        )
        repository = VulnerabilityAnalyticsRepository()
        with (
            patch("app.repositories.vulnerabilities.db.init_db"),
            patch("app.repositories.vulnerabilities.db.connect", return_value=connection),
        ):
            result = repository.summary()

        self.assertEqual(result["filters"]["asset_id"], "")
        self.assertEqual(result["filters"]["has_fix"], "")
        self.assertEqual(result["filters"]["fix_q"], "")
        self.assertEqual(result["top_vulnerabilities"][0]["how_to_fix"], "Установить патч")
        self.assertTrue(result["top_vulnerabilities"][0]["has_fix"])
        # the top-vulnerabilities query itself does not scan the passports tables
        top_sql = connection.queries[3][0]
        self.assertNotIn("asset_card_vulnerability_passports", top_sql)
        self.assertNotIn("fix_rollup", top_sql)
        # the bounded follow-up query covers only the top selectors
        fix_sql, fix_params = connection.queries[4]
        self.assertIn("asset_card_vulnerability_passports", fix_sql)
        self.assertEqual(fix_params, ["cve:CVE-1"])

    def test_list_keeps_findings_and_affected_hosts_as_different_grains(self):
        connection = FakeConnection(
            [
                [{"count": 1}],
                [
                    {
                        "selector": "cve:CVE-2026-1",
                        "vulnerability_id": None,
                        "cve": "CVE-2026-1",
                        "name": "Example vulnerability",
                        "severity": "high",
                        "cvss_score": Decimal("8.1"),
                        "affected_hosts": 2,
                        "findings": 3,
                        "affected_objects": 2,
                        "components": ["OpenSSL", "nginx"],
                        "sources": ["software"],
                        "docker_containers": [],
                        "docker_images": [],
                        "passports": [
                            {
                                "internal_id": "passport-1",
                                "name": "Example vulnerability passport",
                                "short_description": "Memory corruption in OpenSSL.",
                            }
                        ],
                        "last_seen": "2026-07-11T08:00:00+00:00",
                    }
                ],
                [],
            ]
        )
        repository = VulnerabilityAnalyticsRepository()
        with (
            patch("app.repositories.vulnerabilities.db.init_db"),
            patch("app.repositories.vulnerabilities.db.connect", return_value=connection),
        ):
            result = repository.list(limit=50)

        self.assertEqual(result["total"], 1)
        self.assertEqual(result["rows"][0]["affected_hosts"], 2)
        self.assertEqual(result["rows"][0]["findings"], 3)
        self.assertEqual(result["rows"][0]["cvss_score"], 8.1)
        self.assertEqual(result["rows"][0]["max_cvss"], 8.1)
        self.assertEqual(result["rows"][0]["components"], ["OpenSSL", "nginx"])
        self.assertEqual(
            result["rows"][0]["short_description"],
            "Memory corruption in OpenSSL.",
        )
        self.assertEqual(result["rows"][0]["passports"][0]["internal_id"], "passport-1")
        aggregate_sql = connection.queries[1][0]
        self.assertIn("COUNT(DISTINCT asset_id) AS affected_hosts", aggregate_sql)
        self.assertIn("COUNT(*) AS findings", aggregate_sql)
        self.assertIn("COUNT(DISTINCT group_id) AS affected_objects", aggregate_sql)
        self.assertIn("AS components", aggregate_sql)
        self.assertIn("AS docker_containers", aggregate_sql)
        self.assertIn("AS docker_images", aggregate_sql)
        self.assertIn("'short_description', short_description", aggregate_sql)
        self.assertIn("asset_card_vulnerability_passports", aggregate_sql)
        self.assertIn("JSONB_AGG", aggregate_sql)

    def test_summary_exposes_freshness_and_incomplete_coverage(self):
        connection = FakeConnection(
            [
                [
                    {
                        "cards_total": 3,
                        "cards_with_findings": 2,
                        "truncated_groups": 1,
                        "oldest_at": "2026-07-10T08:00:00+00:00",
                        "freshest_at": "2026-07-11T08:00:00+00:00",
                    }
                ],
                [
                    {
                        "affected_hosts": 2,
                        "findings": 5,
                        "unique_vulnerabilities": 3,
                        "unique_cves": 2,
                        "high_risk_hosts": 1,
                        "unrated_vulnerabilities": 1,
                    }
                ],
                [
                    {
                        "severity": "high",
                        "severity_rank": 2,
                        "findings": 2,
                        "affected_hosts": 1,
                        "unique_vulnerabilities": 1,
                    },
                    {
                        "severity": "unknown",
                        "severity_rank": 5,
                        "findings": 1,
                        "affected_hosts": 1,
                        "unique_vulnerabilities": 1,
                    },
                ],
                [
                    {
                        "selector": "cve:CVE-1",
                        "vulnerability_id": None,
                        "cve": "CVE-1",
                        "name": "Example vulnerability",
                        "severity": "high",
                        "cvss_score": Decimal("8.1"),
                        "affected_hosts": 2,
                        "findings": 4,
                        "affected_objects": 2,
                        "components": ["OpenSSL"],
                        "sources": ["software"],
                        "docker_containers": [],
                        "docker_images": [],
                        "passports": [],
                        "last_seen": "2026-07-11T08:00:00+00:00",
                    }
                ],
                [
                    {
                        "selector": "cve:CVE-1",
                        "how_to_fix": "Установить патч",
                    }
                ],
                [
                    {
                        "asset_id": "asset-1",
                        "display_name": "Server 01",
                        "finding_count": 4,
                        "unique_vulnerabilities": 2,
                        "high_risk_vulnerabilities": 1,
                        "severity": "high",
                        "sources": ["software"],
                        "docker_containers": [],
                        "docker_images": [],
                    }
                ],
            ]
        )
        repository = VulnerabilityAnalyticsRepository()
        with (
            patch("app.repositories.vulnerabilities.db.init_db"),
            patch(
                "app.repositories.vulnerabilities.db.connect",
                return_value=connection,
            ),
        ):
            result = repository.summary(source="software")

        self.assertEqual(result["totals"]["hosts_total"], 3)
        self.assertEqual(result["totals"]["affected_hosts"], 2)
        self.assertFalse(result["coverage"]["complete"])
        self.assertEqual(result["coverage"]["truncated_groups"], 1)
        self.assertEqual(result["source"]["as_of"], "2026-07-11T08:00:00+00:00")
        self.assertEqual(result["by_severity"][1]["severity"], "unknown")
        self.assertEqual(result["top_vulnerabilities"][0]["selector"], "cve:CVE-1")
        self.assertEqual(result["top_vulnerabilities"][0]["passports"], [])
        self.assertEqual(result["top_vulnerabilities"][0]["how_to_fix"], "Установить патч")
        self.assertTrue(result["top_vulnerabilities"][0]["has_fix"])
        self.assertEqual(result["top_hosts"][0]["finding_count"], 4)
        top_sql = connection.queries[3][0]
        # the top-vulnerabilities query itself does not scan the passports tables
        self.assertNotIn("asset_card_vulnerability_passports", top_sql)
        # the passport lookup must be parameterized, not interpolated
        self.assertNotIn("asset-1", top_sql)
        fix_sql, fix_params = connection.queries[4]
        self.assertIn("asset_card_vulnerability_passports", fix_sql)
        self.assertEqual(fix_params, ["cve:CVE-1"])

    def test_hosts_returns_one_aggregated_row_per_asset(self):
        connection = FakeConnection(
            [
                [
                    {
                        "selector": "cve:CVE-2026-1",
                        "vulnerability_id": None,
                        "cve": "CVE-2026-1",
                        "name": "Example vulnerability",
                        "severity": "high",
                        "cvss_score": Decimal("8.1"),
                        "affected_hosts": 1,
                        "findings": 2,
                        "affected_objects": 2,
                        "sources": ["software"],
                        "last_seen": "2026-07-11T08:00:00+00:00",
                    }
                ],
                [
                    {
                        "selector": "cve:CVE-2026-1",
                        "how_to_fix": "Обновить компонент",
                    }
                ],
                [{"count": 1}],
                [
                    {
                        "asset_id": "asset-1",
                        "display_name": "Server 01",
                        "hostname": "server-01",
                        "fqdn": "server-01.example.test",
                        "ip_address": "10.0.0.10",
                        "os_name": "Windows Server",
                        "os_version": "2022",
                        "asset_type": "host",
                        "severity": "high",
                        "cvss_score": Decimal("8.1"),
                        "finding_count": 2,
                        "unique_vulnerabilities": 1,
                        "high_risk_vulnerabilities": 1,
                        "objects": ["Package A", "Package B"],
                        "sources": ["software"],
                        "last_seen": "2026-07-11T08:00:00+00:00",
                        "remediation_case_id": "case-1",
                        "remediation_version": 4,
                        "remediation_status": "open",
                        "remediation_assignee": "security-team",
                        "remediation_due_at": "2026-07-20T08:00:00+00:00",
                        "remediation_resolved_at": None,
                        "remediation_overdue": True,
                    }
                ],
            ]
        )
        repository = VulnerabilityAnalyticsRepository()
        with (
            patch("app.repositories.vulnerabilities.db.init_db"),
            patch("app.repositories.vulnerabilities.db.connect", return_value=connection),
        ):
            result = repository.hosts(selector="cve:CVE-2026-1")

        self.assertEqual(result["total"], 1)
        self.assertEqual(result["selection"]["findings"], 2)
        self.assertEqual(result["selection"]["how_to_fix"], "Обновить компонент")
        self.assertTrue(result["selection"]["has_fix"])
        self.assertEqual(result["rows"][0]["finding_count"], 2)
        self.assertEqual(result["rows"][0]["objects"], ["Package A", "Package B"])
        self.assertEqual(result["rows"][0]["remediation"]["case_id"], "case-1")
        self.assertEqual(result["rows"][0]["remediation"]["version"], 4)
        self.assertTrue(result["rows"][0]["remediation"]["overdue"])
        self.assertIn("GROUP BY asset_id", connection.queries[3][0])
        self.assertIn("LEFT JOIN remediation_cases", connection.queries[3][0])
        self.assertEqual(connection.queries[3][1][-1], "cve:CVE-2026-1")
        fix_sql, fix_params = connection.queries[1]
        self.assertIn("asset_card_vulnerability_passports", fix_sql)
        self.assertEqual(fix_params, ["cve:CVE-2026-1"])

    def test_trending_counts_distinct_hosts_and_keeps_unmapped_passports(self):
        connection = FakeConnection(
            [
                [
                    {
                        "internal_id": "passport-trend-1",
                        "external_id": "CVE-2026-58644",
                        "name": "SharePoint remote code execution",
                        "severity": "critical",
                        "score": Decimal("9.8"),
                        "score_numeric": Decimal("9.8"),
                        "description": "Remote code execution in SharePoint Server.",
                        "issue_time": "2026-07-10T08:00:00+00:00",
                        "is_trend_since": "2026-07-16T13:00:00+00:00",
                        "vendors_json": ["Microsoft"],
                        "affected_components_json": [
                            "Microsoft SharePoint Server"
                        ],
                        "affected_hosts": 2,
                        "affected_hosts_total": 2,
                        "docker_affected_hosts": 1,
                        "software_os_affected_hosts": 2,
                        "findings": 3,
                        "findings_total": 3,
                        "docker_findings": 1,
                        "software_os_findings": 2,
                        "sources": ["docker", "software"],
                        "docker_containers": ["sharepoint-api"],
                        "docker_images": ["registry.example/sharepoint:latest"],
                        "trend_total": 2,
                    },
                    {
                        "internal_id": "passport-trend-2",
                        "external_id": "CVE-2026-42980",
                        "name": "Windows privilege escalation",
                        "severity": "high",
                        "score": None,
                        "score_numeric": None,
                        "description": None,
                        "issue_time": "2026-07-09T08:00:00+00:00",
                        "is_trend_since": "2026-07-15T13:00:00+00:00",
                        "vendors_json": ["Microsoft"],
                        "affected_components_json": ["Windows"],
                        "affected_hosts": None,
                        "trend_total": 2,
                    },
                ]
            ]
        )
        repository = VulnerabilityAnalyticsRepository()
        with (
            patch("app.repositories.vulnerabilities.db.init_db"),
            patch(
                "app.repositories.vulnerabilities.db.connect",
                return_value=connection,
            ),
        ):
            result = repository.trending(limit=20)

        self.assertEqual(result["total"], 2)
        self.assertEqual(result["limit"], 20)
        self.assertEqual(result["rows"][0]["internal_id"], "passport-trend-1")
        self.assertEqual(result["rows"][0]["score"], 9.8)
        self.assertEqual(result["rows"][0]["affected_hosts"], 2)
        self.assertEqual(result["rows"][0]["contexts"], ["docker", "software_os"])
        self.assertEqual(result["rows"][0]["docker_affected_hosts"], 1)
        self.assertEqual(result["rows"][0]["software_os_affected_hosts"], 2)
        self.assertEqual(result["rows"][0]["docker_containers"], ["sharepoint-api"])
        self.assertEqual(
            result["rows"][0]["docker_images"],
            ["registry.example/sharepoint:latest"],
        )
        self.assertEqual(result["rows"][0]["vendors"], ["Microsoft"])
        self.assertEqual(
            result["rows"][0]["affected_components"],
            ["Microsoft SharePoint Server"],
        )
        self.assertEqual(result["rows"][1]["affected_hosts"], 0)

        sql, params = connection.queries[0]
        normalized_sql = " ".join(sql.split())
        self.assertIn("vulnerability_passport_trends", normalized_sql)
        self.assertRegex(
            normalized_sql,
            re.compile(
                r"COUNT\s*\(\s*DISTINCT\s+asset_id\s*\)",
                re.IGNORECASE,
            ),
        )
        self.assertIn("JOIN asset_card_vulnerability_passports", normalized_sql)
        self.assertGreater(
            normalized_sql.index("LIMIT %s"),
            normalized_sql.index("COUNT(DISTINCT asset_id)"),
        )
        self.assertIn(
            "JOIN asset_card_vulnerabilities",
            normalized_sql,
        )
        self.assertIn("LEFT JOIN host_counts", normalized_sql)
        self.assertRegex(
            normalized_sql,
            re.compile(
                r"ORDER BY\s+filtered_trends\.affected_hosts\s+DESC\s*,\s*filtered_trends\.is_trend_since\s+DESC\s+NULLS\s+LAST",
                re.IGNORECASE,
            ),
        )
        self.assertEqual(params, [20])

    def test_trending_docker_context_filters_before_limit(self):
        connection = FakeConnection([[]])
        repository = VulnerabilityAnalyticsRepository()
        with (
            patch("app.repositories.vulnerabilities.db.init_db"),
            patch(
                "app.repositories.vulnerabilities.db.connect",
                return_value=connection,
            ),
        ):
            result = repository.trending(limit=20, context="docker")

        sql, params = connection.queries[0]
        normalized_sql = " ".join(sql.split())
        self.assertIn(
            "WHERE COALESCE(host_counts.docker_affected_hosts, 0) > 0",
            normalized_sql,
        )
        self.assertIn(
            "COALESCE(host_counts.docker_affected_hosts, 0) AS affected_hosts",
            normalized_sql,
        )
        self.assertLess(
            normalized_sql.index("docker_affected_hosts, 0) > 0"),
            normalized_sql.index("LIMIT %s"),
        )
        self.assertEqual(params, [20])
        self.assertEqual(result["context"], "docker")

    def test_invalid_sort_is_rejected_before_querying(self):
        with self.assertRaisesRegex(ValueError, "Unsupported sort column"):
            VulnerabilityAnalyticsRepository().list(sort_by="drop_table")

    def test_list_loads_passports_only_after_page_is_selected(self):
        connection = FakeConnection(
            [
                [{"count": 2}],
                [],
                [],
            ]
        )
        repository = VulnerabilityAnalyticsRepository()
        with (
            patch("app.repositories.vulnerabilities.db.init_db"),
            patch(
                "app.repositories.vulnerabilities.db.connect",
                return_value=connection,
            ),
        ):
            repository.list(limit=1, offset=1)

        query = " ".join(connection.queries[1][0].split())
        self.assertIn("paged AS", query)
        self.assertIn("FROM paged", query)
        self.assertNotIn("FROM filtered_findings JOIN asset_card_vulnerability_passports", query)
        self.assertLess(query.index("LIMIT %s"), query.index("asset_card_vulnerability_passports"))

    def test_count_projection_keeps_filters_without_loading_details(self):
        filters = dict(q="CVE", host_q="srv", os="Linux", asset_type="host",
                       severity="high", source="docker")
        full_sql, full_params = _filtered_findings_cte(**filters)
        count_sql, count_params = _filtered_findings_cte(**filters, include_details=False)
        self.assertEqual(count_params, full_params)
        self.assertEqual(count_sql.split("WHERE", 1)[1], full_sql.split("WHERE", 1)[1])
        self.assertNotIn("::jsonb", count_sql)
        self.assertNotIn("AS finding_id", count_sql)
        self.assertIn("AS selector", count_sql)
        self.assertNotRegex(count_sql, r",\s*FROM")

    def test_list_renders_both_sort_clauses_without_total_query(self):
        for sort_by in ("affected_hosts", "findings", "severity", "cvss_score",
                        "max_cvss", "name", "cve", "last_seen"):
            for direction in ("asc", "desc"):
                with self.subTest(sort_by=sort_by, direction=direction):
                    connection = FakeConnection([[]])
                    with (
                        patch("app.repositories.vulnerabilities.db.init_db"),
                        patch("app.repositories.vulnerabilities.db.connect", return_value=connection),
                    ):
                        result = VulnerabilityAnalyticsRepository().list(
                            sort_by=sort_by, sort_dir=direction, include_total=False,
                            limit=3, offset=9,
                        )
                    self.assertEqual(result, {"total": 0, "rows": [], "limit": 3, "offset": 9})
                    self.assertEqual(len(connection.queries), 1)
                    sql, params = connection.queries[0]
                    self.assertNotIn("{expression}", sql)
                    self.assertNotIn("{direction}", sql)
                    self.assertEqual(sql.count(f"{direction.upper()} NULLS LAST"), 2)
                    self.assertEqual(params, [3, 9])

    def test_hosts_pages_before_joining_remediation_cases(self):
        connection = FakeConnection([[], [{"count": 2}], []])
        with (
            patch("app.repositories.vulnerabilities.db.init_db"),
            patch("app.repositories.vulnerabilities.db.connect", return_value=connection),
        ):
            result = VulnerabilityAnalyticsRepository().hosts(
                selector="cve:CVE-1", limit=2, offset=4
            )

        self.assertEqual(result["total"], 2)
        sql, params = connection.queries[2]
        normalized_sql = " ".join(sql.split())
        self.assertIn("paged_hosts AS", normalized_sql)
        self.assertNotIn("{expression}", normalized_sql)
        self.assertNotIn("{direction}", normalized_sql)
        self.assertIn("FROM paged_hosts AS aggregated_hosts", normalized_sql)
        self.assertLess(normalized_sql.index("LIMIT %s"), normalized_sql.index("JOIN remediation_cases"))
        self.assertEqual(params[-3:], [2, 4, "cve:CVE-1"])


class VulnerabilityApiContractTests(unittest.TestCase):
    def test_openapi_exposes_dashboard_paths_and_domain_tag(self):
        schema = main.app.openapi()
        self.assertIn("/api/vulnerabilities/summary", schema["paths"])
        self.assertIn("/api/vulnerabilities/trending", schema["paths"])
        self.assertIn("/api/vulnerabilities", schema["paths"])
        self.assertIn("/api/vulnerabilities/hosts", schema["paths"])
        self.assertEqual(
            schema["paths"]["/api/vulnerabilities/summary"]["get"]["tags"],
            ["vulnerabilities"],
        )
        self.assertEqual(
            schema["paths"]["/api/vulnerabilities/trending"]["get"]["tags"],
            ["vulnerabilities"],
        )

    def test_summary_endpoint_uses_the_container_service_and_forwards_filters(self):
        from fastapi.testclient import TestClient

        service = main.CONTAINER.services.vulnerabilities
        with patch.object(service, "summary", return_value={"totals": {"findings": 3}}) as summary, patch.object(
            main.app_auth, "get_session_user", return_value={"id": 1, "role": "viewer"}
        ):
            response = TestClient(main.app).get(
                "/api/vulnerabilities/summary",
                params={
                    "q": "CVE-1",
                    "host_q": "srv",
                    "os": "Windows",
                    "asset_type": "host",
                    "asset_id": "asset-1",
                    "severity": "high",
                    "source": "docker",
                    "has_fix": "yes",
                    "fix_q": "обновить",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["totals"]["findings"], 3)
        summary.assert_called_once_with(
            q="CVE-1",
            host_q="srv",
            os="Windows",
            asset_type="host",
            asset_id="asset-1",
            severity="high",
            source="docker",
            has_fix="yes",
            fix_q="обновить",
        )

    def test_trending_endpoint_uses_default_limit_and_returns_current_snapshot(self):
        from fastapi.testclient import TestClient

        service = main.CONTAINER.services.vulnerabilities
        payload = {
            "rows": [
                {
                    "internal_id": "passport-trend-1",
                    "external_id": "CVE-2026-58644",
                    "affected_hosts": 2,
                }
            ],
            "total": 1,
            "limit": 20,
        }
        with patch.object(
            service,
            "trending",
            return_value=payload,
        ) as trending, patch.object(
            main.app_auth,
            "get_session_user",
            return_value={"id": 1, "role": "viewer"},
        ):
            response = TestClient(main.app).get("/api/vulnerabilities/trending")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), payload)
        trending.assert_called_once_with(limit=20, context="all")

    def test_trending_endpoint_restricts_limit_to_one_hundred(self):
        from fastapi.testclient import TestClient

        service = main.CONTAINER.services.vulnerabilities
        with patch.object(
            service,
            "trending",
            return_value={"rows": [], "total": 0, "limit": 100},
        ) as trending, patch.object(
            main.app_auth,
            "get_session_user",
            return_value={"id": 1, "role": "viewer"},
        ):
            client = TestClient(main.app)
            allowed = client.get(
                "/api/vulnerabilities/trending",
                params={"limit": 100, "context": "docker"},
            )
            too_small = client.get("/api/vulnerabilities/trending", params={"limit": 0})
            too_large = client.get("/api/vulnerabilities/trending", params={"limit": 101})

        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(too_small.status_code, 422)
        self.assertEqual(too_large.status_code, 422)
        trending.assert_called_once_with(limit=100, context="docker")

    def test_invalid_service_sort_is_returned_as_422(self):
        from fastapi.testclient import TestClient

        service = main.CONTAINER.services.vulnerabilities
        with patch.object(service, "list", side_effect=ValueError("Unsupported sort column")), patch.object(
            main.app_auth, "get_session_user", return_value={"id": 1, "role": "viewer"}
        ):
            response = TestClient(main.app).get(
                "/api/vulnerabilities",
                params={"sort_by": "not_allowed"},
            )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["detail"]["code"], "INVALID_SORT")

    def test_host_remediation_metadata_requires_remediation_read_permission(self):
        from fastapi.testclient import TestClient

        service = main.CONTAINER.services.vulnerabilities
        payload = {
            "selection": None,
            "total": 1,
            "rows": [
                {
                    "asset_id": "asset-1",
                    "remediation": {
                        "case_id": "case-1",
                        "status": "open",
                        "assignee": "security-team",
                    },
                }
            ],
        }
        with patch.object(service, "hosts", return_value=payload), patch.object(
            main.app_auth,
            "get_session_user",
            return_value={
                "id": 1,
                "role": "asset-auditor",
                "permissions": ["assets.read"],
            },
        ):
            response = TestClient(main.app).get(
                "/api/vulnerabilities/hosts",
                params={"selector": "cve:CVE-2026-1"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("remediation", response.json()["rows"][0])


if __name__ == "__main__":
    unittest.main()
