from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import db, main


class AssetCardReadApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)

    def test_overview_is_compact_and_has_etag(self):
        payload = {
            "asset": {"asset_id": "asset-1", "display_name": "Fixture"},
            "root": {"displayName": "Fixture"},
            "stats": {"table_rows": 5000},
            "sections": ["summary", "configuration", "vulnerabilities"],
            "version": "2026-07-02T00:00:00+00:00",
        }
        with patch("app.api.asset_cards.asset_card_reads.get_overview", return_value=payload):
            response = self.client.get("/api/asset-cards/asset-1/overview")

        self.assertEqual(response.status_code, 200)
        self.assertIn("etag", response.headers)
        self.assertNotIn("nodes", response.json())
        self.assertNotIn("collections", response.json())

    def test_matching_etag_returns_not_modified(self):
        payload = {"asset": {"asset_id": "asset-1"}, "version": "v1"}
        with patch("app.api.asset_cards.asset_card_reads.get_overview", return_value=payload):
            first = self.client.get("/api/asset-cards/asset-1/overview")
            second = self.client.get(
                "/api/asset-cards/asset-1/overview",
                headers={"If-None-Match": first.headers["etag"]},
            )
        self.assertEqual(second.status_code, 304)
        self.assertEqual(second.content, b"")

    def test_tree_cursor_is_validated(self):
        response = self.client.get("/api/asset-cards/asset-1/configuration/tree?cursor=bad")
        self.assertEqual(response.status_code, 422)


class AssetCardPathTests(unittest.TestCase):
    def test_parent_path_supports_properties_and_collection_items(self):
        self.assertEqual(db.asset_card_parent_path("asset.software"), "asset")
        self.assertEqual(db.asset_card_parent_path("asset.software[12]"), "asset.software")
        self.assertIsNone(db.asset_card_parent_path("asset"))


if __name__ == "__main__":
    unittest.main()
