"""Regression tests: only assets confirmed saved by the import run are removed after export."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

from app import db
from app.services.scanner_task_launch import remove_assets_after_export

U1 = "11111111-2222-3333-4444-555555555555"
U2 = "22222222-3333-4444-5555-666666666666"
U3 = "33333333-4444-5555-6666-777777777777"

CSV_WITH_IDS = "\n".join(
    ["AssetId;Host.IpAddress", f"{U1};10.0.0.1", f"{U2};10.0.0.2", f"{U3};10.0.0.3"]
)


def _fake_client() -> SimpleNamespace:
    return SimpleNamespace(
        remove_assets=Mock(return_value="op-1"),
        wait_for_asset_removal=Mock(return_value=(True, "removed", {"ok": True})),
    )


def _call(monkeypatch, *, csv_text: str, import_run_id: int | None, confirmed: object):
    record = Mock()
    monkeypatch.setattr(db, "record_asset_removal", record)
    monkeypatch.setattr(db, "get_confirmed_exported_asset_ids", Mock(return_value=confirmed))
    client = _fake_client()
    result = remove_assets_after_export(
        client=client,
        token="tok",
        csv_text=csv_text,
        import_run_id=import_run_id,
        utc_offset=None,
        group_ids=[],
        include_nested_groups=False,
        timeout_minutes=1,
        poll_seconds=1,
    )
    return client, record, result


def test_empty_csv_is_skipped(monkeypatch):
    client, record, result = _call(monkeypatch, csv_text="", import_run_id=7, confirmed=[U1])
    assert result["status"] == "skipped"
    assert result["asset_count"] == 0
    assert result["message"] == "No asset IDs found in the exported CSV; nothing was removed."
    client.remove_assets.assert_not_called()
    assert record.call_args.kwargs["status"] == "skipped"
    assert record.call_args.kwargs["asset_ids"] == []


def test_csv_without_asset_ids_is_skipped(monkeypatch):
    # Original bug: the old code substituted caller-provided asset_ids here; that path no longer exists.
    client, record, result = _call(
        monkeypatch, csv_text="Name;IP\nhost-1;10.0.0.1\n", import_run_id=7, confirmed=[U1]
    )
    assert result["status"] == "skipped"
    assert result["asset_count"] == 0
    client.remove_assets.assert_not_called()
    assert record.call_args.kwargs["status"] == "skipped"


def test_missing_import_run_is_skipped(monkeypatch):
    client, record, result = _call(monkeypatch, csv_text=CSV_WITH_IDS, import_run_id=None, confirmed=[U1])
    assert result["status"] == "skipped"
    assert result["asset_count"] == 0
    assert result["message"] == (
        "No local import run is recorded for this export, so the local save is not confirmed; nothing was removed."
    )
    client.remove_assets.assert_not_called()
    assert record.call_args.kwargs["status"] == "skipped"


def test_incomplete_import_run_is_skipped(monkeypatch):
    client, record, result = _call(monkeypatch, csv_text=CSV_WITH_IDS, import_run_id=42, confirmed=None)
    assert result["status"] == "skipped"
    assert result["asset_count"] == 0
    assert result["message"] == (
        "Import run 42 did not complete, so the local save is not confirmed; nothing was removed."
    )
    client.remove_assets.assert_not_called()
    assert record.call_args.kwargs["status"] == "skipped"


def test_none_confirmed_is_skipped(monkeypatch):
    other = "44444444-5555-6666-7777-888888888888"
    client, record, result = _call(monkeypatch, csv_text=CSV_WITH_IDS, import_run_id=7, confirmed=[other])
    assert result["status"] == "skipped"
    assert result["asset_count"] == 0
    assert result["message"] == "None of the exported asset IDs is confirmed as saved locally; nothing was removed."
    client.remove_assets.assert_not_called()
    assert record.call_args.kwargs["status"] == "skipped"


def test_partial_confirmation_removes_only_confirmed_ids_in_csv_order(monkeypatch):
    client, record, result = _call(monkeypatch, csv_text=CSV_WITH_IDS, import_run_id=7, confirmed=[U3, U1])
    client.remove_assets.assert_called_once_with("tok", [U1, U3])
    client.wait_for_asset_removal.assert_called_once_with("tok", "op-1", timeout_seconds=60.0, poll_seconds=1)
    assert result["status"] == "completed"
    assert result["operation_id"] == "op-1"
    assert result["asset_count"] == 2
    assert result["resolution_source"] == "export_csv_import_run"
    assert record.call_args.kwargs["asset_ids"] == [U1, U3]
    assert record.call_args.kwargs["status"] == "completed"


def test_all_confirmed_removes_all_with_resolution_source(monkeypatch):
    client, record, result = _call(monkeypatch, csv_text=CSV_WITH_IDS, import_run_id=7, confirmed=[U1, U2, U3])
    client.remove_assets.assert_called_once_with("tok", [U1, U2, U3])
    assert result["status"] == "completed"
    assert result["asset_count"] == 3
    assert result["resolution_source"] == "export_csv_import_run"
    assert record.call_args.kwargs["asset_ids"] == [U1, U2, U3]
    assert record.call_args.kwargs["status"] == "completed"
