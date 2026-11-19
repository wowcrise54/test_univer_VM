from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from app import db
from app.core import get_settings
from app.services.stale_scan_assets import cleanup_stale_scan_assets


@pytest.mark.parametrize("scenario", ["direct", "precheck", "import-only", "fresh-import", "unknown-error", "no-scan"])
def test_stale_unreachable_assets_are_removed_locally(test_db, monkeypatch, scenario):
    address = "192.0.2.1"
    asset_id = "asset-old"
    old = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    monkeypatch.setattr(get_settings(), "scan_unreachable_errors", "confirmed-no-route")
    if scenario != "import-only":
        db.upsert_asset_card({"asset_id": asset_id, "metadata": {"ip_address": address}})
    with db.connect() as conn:
        conn.execute("UPDATE asset_cards SET ip_address = %s, last_seen = %s WHERE asset_id = %s", (address, old, asset_id))
        conn.execute(
            "INSERT INTO assets (asset_key, mp_asset_id, ip_address, first_seen, last_seen) VALUES (%s, %s, %s, %s, %s)",
            (asset_id, asset_id, address, old, datetime.now(UTC).isoformat() if scenario == "fresh-import" else old),
        )
    client = Mock()
    scan = {
        "confirmed_finished_at": None if scenario == "no-scan" else datetime.now(UTC).isoformat(),
        "jobs": [{
            "id": "job-1", "status": "finished", "runMode": "connectionCheck",
            "targets": [address],
            "connectionCheckResults": [{
                "status": "fail", "errors": ["authentication" if scenario == "unknown-error" else "confirmed-no-route"],
            }],
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
    removed = scenario in {"direct", "precheck", "import-only"}
    assert cleanup_stale_scan_assets(client, "token", "run-1", scan, lambda: None, connection_check=connection_check) == int(removed)
    assert db.asset_card_exists(asset_id) is (not removed)
    client.remove_assets.assert_not_called()
    with db.connect() as conn:
        operation = conn.execute("SELECT status, operation_id FROM asset_removal_operations").fetchone()
        imported = conn.execute("SELECT id FROM assets WHERE ip_address = %s", (address,)).fetchone()
    assert bool(imported) is (not removed)
    assert operation == ({"status": "completed", "operation_id": None} if removed else None)
