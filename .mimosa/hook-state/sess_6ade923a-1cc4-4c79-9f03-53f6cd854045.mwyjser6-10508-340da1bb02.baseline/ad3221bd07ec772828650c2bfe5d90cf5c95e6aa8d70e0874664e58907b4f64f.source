"""Search index rebuild runs in a transaction separate from the card save.

Regression contract: after ``upsert_asset_card`` returns, the card row and
its ``asset_card_search_fields`` rows are both committed. Failure
contract: if the search-index step raises, the exception propagates, but
the already-committed ``asset_cards`` row is NOT rolled back.
"""
import pytest

from app import db
from app.repositories.asset_cards import cards

pytestmark = pytest.mark.integration


def _card(asset_id: str = "idx-host-1") -> dict:
    return {
        "asset_id": asset_id,
        "display_name": asset_id,
        "hostname": asset_id,
        "root": {"data": {"fqdn": f"{asset_id}.example", "hostname": asset_id, "ipAddress": "10.99.0.1", "osName": "Ubuntu"}},
        "nodes": [{"path": "os", "data": {"osName": "Ubuntu", "osVersion": "22.04"}}],
        "collections": [{"path": "software", "name": "software", "items": [{"data": {"softName": "nginx", "softVersion": "1.24"}}]}],
    }


def _search_fields(asset_id: str) -> list[dict]:
    with db.connect() as conn:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT entity_path, field_path, field_name, value_text FROM asset_card_search_fields WHERE asset_id = %s",
                (asset_id,),
            ).fetchall()
        ]


def test_upsert_populates_search_index_before_returning(test_db):
    result = db.upsert_asset_card(_card())
    assert result is not None and result["asset_id"] == "idx-host-1"
    fields = _search_fields("idx-host-1")
    # Summary rows, node rows and collection-item rows must all be present
    # before the upsert returns.
    assert any(f["entity_path"] == "asset" and f["value_text"] == "idx-host-1" for f in fields)
    assert any(f["entity_path"] == "os" and f["value_text"] == "22.04" for f in fields)
    assert any(f["entity_path"] == "software[0]" and f["value_text"] == "nginx" for f in fields)


def test_search_index_failure_does_not_rollback_committed_card(test_db, monkeypatch):
    def boom(conn, asset_id, card, updated_at):
        raise RuntimeError("index rebuild failed")

    monkeypatch.setattr(cards, "replace_asset_card_search_index", boom)
    with pytest.raises(RuntimeError, match="index rebuild failed"):
        db.upsert_asset_card(_card())
    with db.connect() as conn:
        row = conn.execute(
            "SELECT asset_id, display_name, hostname FROM asset_cards WHERE asset_id = %s",
            ("idx-host-1",),
        ).fetchone()
    assert row is not None and row["display_name"] == "idx-host-1" and row["hostname"] == "idx-host-1"
