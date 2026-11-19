from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from app import db
from app.core import get_settings
from app.services.stale_scan_assets import cleanup_stale_scan_assets


@pytest.mark.parametrize("scenario", ["direct", "precheck", "resume"])
def test_card_removed_only_after_remote_confirmation(test_db, monkeypatch, scenario):
    address = "192.0.2.1"
    asset_id = "asset-old"
    old = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    monkeypatch.setattr(get_settings(), "scan_unreachable_errors", "confirmed-no-route")
    db.upsert_asset_card({"asset_id": asset_id, "metadata": {"ip_address": address}})
    with db.connect() as conn:
        conn.execute("UPDATE asset_cards SET ip_address = %s, last_seen = %s WHERE asset_id = %s", (address, old, asset_id))
    client = Mock()
    client.fetch_asset_grid_data.return_value = {
        "total": 1,
        "rows": [{
            "AssetId": asset_id, "IpAddress": address, "AllAddresses": [address],
            "CreationTime": old, "UpdateTime": old, "AuditTime": old, "PentestTime": None,
        }],
    }
    client.remove_assets.return_value = "operation-1"
    client.wait_for_asset_removal.return_value = (scenario != "resume", "", None)
    scan = {
        "confirmed_finished_at": datetime.now(UTC).isoformat(),
        "jobs": [{
            "id": "job-1", "status": "finished", "runMode": "connectionCheck",
            "targets": [address],
            "connectionCheckResults": [{"status": "fail", "errors": ["confirmed-no-route"]}],
        }],
    }

    connection_check = None
    if scenario == "precheck":
        started = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
        finished = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
        connection_check = {"task_id": "precheck", "started_from": started}
        client.get_task_runs.return_value = [{"id": "precheck-run", "status": "finished", "finishedAt": finished}]
        client.get_all_run_jobs.return_value = scan.pop("jobs")
        scan["jobs"] = []
    if scenario == "resume":
        with pytest.raises(RuntimeError, match="did not confirm"):
            cleanup_stale_scan_assets(client, "token", "run-1", scan, lambda: None)
        assert db.asset_card_exists(asset_id)
        client.wait_for_asset_removal.return_value = (True, "", None)
        scan = {}

    assert cleanup_stale_scan_assets(client, "token", "run-1", scan, lambda: None, connection_check=connection_check) == 1
    assert not db.asset_card_exists(asset_id)
    client.remove_assets.assert_called_once_with("token", [asset_id])
    with db.connect() as conn:
        operation = conn.execute("SELECT status, operation_id FROM asset_removal_operations").fetchone()
    assert operation == {"status": "completed", "operation_id": "operation-1"}
