from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock, patch

import pytest

from app.repositories.attention import AttentionRepository, decode_cursor, encode_cursor


def test_cursor_round_trip_and_invalid_payloads():
    assert decode_cursor(None) == 0
    assert decode_cursor(encode_cursor(42)) == 42
    for payload in ([], {"offset": -1}, {"offset": "2"}):
        cursor = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        with pytest.raises(ValueError):
            decode_cursor(cursor)


def test_attention_filters_before_pagination():
    repository = AttentionRepository()
    rows = [
        {"id": "1", "type": "operation", "priority": "high"},
        {"id": "2", "type": "case", "priority": "critical"},
        {"id": "3", "type": "case", "priority": "critical"},
    ]
    with patch.object(repository, "_rows", return_value=rows):
        first = repository.attention(permissions={"remediation.read"}, kind="case", priority="critical", limit=1, cursor=None)
        second = repository.attention(permissions={"remediation.read"}, kind="case", priority="critical", limit=1, cursor=first["next_cursor"])
    assert first["total"] == 2
    assert [row["id"] for row in first["items"]] == ["2"]
    assert [row["id"] for row in second["items"]] == ["3"]
    assert second["next_cursor"] is None


def test_search_skips_inaccessible_categories():
    connection = MagicMock()
    with patch("app.repositories.attention.db.init_db"), patch("app.repositories.attention.db.connect") as connect:
        connect.return_value.__enter__.return_value = connection
        result = AttentionRepository().search(query="host", kind=None, permissions=set(), limit=20, cursor=None)
    assert result == {"items": [], "next_cursor": None}
    connection.execute.assert_not_called()


def test_search_escapes_wildcards_and_checks_card_permission():
    connection = MagicMock()
    connection.execute.return_value.fetchall.return_value = []
    with patch("app.repositories.attention.db.init_db"), patch("app.repositories.attention.db.connect") as connect:
        connect.return_value.__enter__.return_value = connection
        AttentionRepository().search(query="host_%", kind="asset", permissions={"asset_cards.read"}, limit=20, cursor=None)
    assert connection.execute.call_args.args[1] == ("host\\_\\%%",) * 4


def test_blank_search_is_rejected():
    with patch("app.repositories.attention.db.init_db"), pytest.raises(ValueError):
        AttentionRepository().search(query="  ", kind=None, permissions=set(), limit=20, cursor=None)
