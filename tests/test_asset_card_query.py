from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from psycopg._queries import PostgresQuery
from psycopg.adapt import Transformer

from app import db


class AssetCardSearchIndexTests(unittest.TestCase):
    def fixture(self):
        return {
            "asset_id": "asset-1",
            "display_name": "host-1",
            "root": {"data": {"hostname": "host-1", "rawCard": {"secret": "hidden"}, "type": "Host"}},
            "collections": [{
                "path": "asset.firewall.rules",
                "items": [
                    {"data": {"port": 443, "action": "allow", "enabled": True}},
                    {"data": {"port": 22, "action": "deny", "raw_value": {"debug": 1}}},
                ],
            }],
        }

    def test_index_keeps_typed_leaf_values_and_omits_raw_containers(self):
        rows = db.build_asset_card_search_rows(self.fixture())
        by_path = {(row[0], row[1]): row for row in rows}

        self.assertEqual(by_path[("asset.firewall.rules[0]", "asset.firewall.rules.port")][3], "number")
        self.assertEqual(by_path[("asset.firewall.rules[0]", "asset.firewall.rules.port")][6], 443)
        self.assertIs(by_path[("asset.firewall.rules[0]", "asset.firewall.rules.enabled")][7], True)
        self.assertTrue(all("raw" not in row[1].lower() for row in rows))
        self.assertTrue(all(not row[1].endswith(".type") for row in rows))

    def test_same_entity_intersection_cannot_mix_two_firewall_rules(self):
        rows = db.build_asset_card_search_rows(self.fixture())
        port_entities = {entity for entity, path, *_rest in rows if path == "asset.firewall.rules.port" and _rest[4] == 443}
        deny_entities = {entity for entity, path, *_rest in rows if path == "asset.firewall.rules.action" and _rest[3] == "deny"}
        self.assertEqual(port_entities & deny_entities, set())

        sql, params, scope = db.compile_asset_query_node({
            "combinator": "and",
            "match_scope": "same_entity",
            "rules": [
                {"field_path": "asset.firewall.rules.port", "operator": "equals", "value": 443},
                {"field_path": "asset.firewall.rules.action", "operator": "equals", "value": "deny"},
            ],
        })
        self.assertEqual(scope, "same_entity")
        self.assertIn("INTERSECT", sql)
        self.assertNotIn("NULL::text AS entity_path", sql)
        self.assertEqual(params, [
            "asset.firewall.rules.port", "443", "443",
            "asset.firewall.rules.action", "deny", "deny",
        ])

    def test_software_inventory_extracts_one_row_per_software_entity(self):
        card = {
            "asset_id": "asset-windows-1",
            "asset_type": "WindowsHost",
            "os_name": "Microsoft Windows Server 2022",
            "collections": [{
                "path": "asset.WindowsHost.Softs",
                "items": [{
                    "path": "asset.WindowsHost.Softs[0]",
                    "data": {
                        "Name": "OpenSSL",
                        "Version": "3.2.1",
                        "Vendor": "OpenSSL Project",
                        "Architecture": "x64",
                        "InstallPath": "C:/OpenSSL",
                    },
                }],
            }],
        }

        rows = db.build_asset_card_software_inventory_rows(card)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "asset-windows-1")
        self.assertEqual(rows[0][2:6], ("OpenSSL", "openssl", "3.2.1", "3.2.1"))
        self.assertEqual(rows[0][6:9], ("OpenSSL Project", "x64", "C:/OpenSSL"))
        self.assertTrue(rows[0][9])

    def test_long_text_equality_uses_digest_and_full_value_check(self):
        value = "x" * 5000
        sql, params, scope = db.compile_asset_query_rule({
            "field_path": "asset.notes",
            "operator": "equals",
            "value": value,
        })

        self.assertEqual(scope, "entity")
        self.assertIn("md5(value_text_normalized) = md5(%s)", sql)
        self.assertIn("value_text_normalized = %s", sql)
        self.assertEqual(params, ["asset.notes", value, value])

    def test_software_inventory_excludes_nested_metadata(self):
        card = {
            "asset_id": "host",
            "collections": [
                {"path": path, "items": [{"data": data}]}
                for path, data in [
                    ("asset.Host.Softs", {"Name": "Docker Engine", "Version": "28"}),
                    ("asset.Host.Softs[0].Containers", {"Name": "nginx"}),
                    ("asset.Host.Softs[0].Users", {"Name": "root"}),
                    ("asset.Host.Softs[0].Services", {"Name": "daemon"}),
                ]
            ],
        }
        rows = db.build_asset_card_software_inventory_rows(card)
        self.assertEqual([row[2] for row in rows], ["Docker Engine"])

    def test_query_limits_and_sort_allowlist_are_validated(self):
        too_many = {"combinator": "or", "match_scope": "host", "rules": [
            {"field_path": "asset.hostname", "operator": "exists"} for _ in range(21)
        ]}
        with self.assertRaisesRegex(ValueError, "at most 20"):
            db.validate_asset_query_tree(too_many)
        with self.assertRaisesRegex(ValueError, "Unsupported sort column"):
            db.validated_sort_sql("drop table", "asc", {"name": "name"}, default="name")

    def test_all_requested_local_presets_are_available(self):
        presets = db.list_asset_card_query_presets()

        self.assertEqual(len(presets), 8)
        self.assertEqual(
            [preset["name"] for preset in presets],
            [
                "ПО Windows",
                "ПО Windows, сгруппированное по версиям",
                "Поиск определённого ПО на активах Windows",
                "ПО на активах",
                "ПО на активах, сгруппированное по версиям",
                "Поиск определённого ПО на активах",
                "Вендоры ПО",
                "Версии ОС",
            ],
        )
        self.assertTrue(all(preset["pdql"] for preset in presets))
        self.assertTrue(all(preset.get("kind") in {"software", "os"} for preset in presets))

    @patch.object(db, "asset_card_search_index_coverage", return_value={
        "indexed_cards": 3,
        "total_cards": 3,
    })
    @patch.object(db, "connect")
    @patch.object(db, "init_db")
    def test_software_search_preset_groups_local_index(
        self, _init_db, connect, _coverage,
    ):
        connection = MagicMock()
        connection.execute.return_value.fetchall.return_value = [
            {
                "soft_name": "OpenSSL",
                "soft_version": "3.2.1",
                "count": 4,
                "__total": 1,
            },
        ]
        connect.return_value.__enter__.return_value = connection

        result = db.query_asset_card_preset(
            "software-search",
            software_name="OpenSSL",
            software_version_like="3.%",
        )

        sql, params = connection.execute.call_args.args
        self.assertIn("FROM asset_card_software_inventory", sql)
        self.assertIn("GROUP BY soft_name, soft_version", sql)
        self.assertNotIn("mpvm", sql.lower())
        self.assertEqual(params[:3], [False, "OpenSSL", "3.%"])
        self.assertEqual(result["execution"], "local")
        self.assertEqual(result["rows"][0]["count"], 4)

    def test_software_preset_escapes_percent_like_patterns_for_psycopg(self):
        sql = db.ASSET_SOFTWARE_ROWS_CTE

        self.assertIn("FROM asset_card_software_inventory", sql)
        self.assertIn("inventory.soft_name_normalized", sql)
        self.assertIn("inventory.soft_version_normalized", sql)
        query = PostgresQuery(Transformer())
        query.convert(sql + " SELECT * FROM software_rows", [False])
        self.assertIn(b"asset_card_software_inventory", query.query)

    @patch.object(db, "asset_card_search_index_coverage", return_value={
        "indexed_cards": 3,
        "total_cards": 3,
    })
    @patch.object(db, "connect")
    @patch.object(db, "init_db")
    def test_software_preset_assets_returns_local_hosts(
        self, _init_db, connect, _coverage,
    ):
        connection = MagicMock()
        connection.execute.return_value.fetchall.return_value = [
            {
                "asset_id": "asset-1",
                "display_name": "pc-01",
                "ip_address": "10.0.0.1",
                "soft_name": "AnyDesk",
                "soft_version": "9.5.2",
                "__total": 1,
            },
        ]
        connect.return_value.__enter__.return_value = connection

        result = db.query_asset_card_preset_assets(
            "windows-software-by-version",
            software_name="AnyDesk",
            software_version="9.5.2",
        )

        sql, params = connection.execute.call_args.args
        self.assertIn("selected_assets AS", sql)
        self.assertIn("JOIN asset_cards AS card", sql)
        self.assertEqual(params[:3], [True, "AnyDesk", "9.5.2"])
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["rows"][0]["asset_id"], "asset-1")
        self.assertEqual(result["execution"], "local")


if __name__ == "__main__":
    unittest.main()
