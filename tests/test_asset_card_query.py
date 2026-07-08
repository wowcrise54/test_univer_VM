from __future__ import annotations

import unittest

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

    def test_query_limits_and_sort_allowlist_are_validated(self):
        too_many = {"combinator": "or", "match_scope": "host", "rules": [
            {"field_path": "asset.hostname", "operator": "exists"} for _ in range(21)
        ]}
        with self.assertRaisesRegex(ValueError, "at most 20"):
            db.validate_asset_query_tree(too_many)
        with self.assertRaisesRegex(ValueError, "Unsupported sort column"):
            db.validated_sort_sql("drop table", "asc", {"name": "name"}, default="name")


if __name__ == "__main__":
    unittest.main()
