from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from .. import db
from ..mpvm_client import (
    ASSET_CARD_PDQL,
    DOCKER_VULNERABILITY_PDQL,
    SOFTWARE_VULN_PDQL,
    TRENDING_VULNERABILITY_PDQL,
    VULNER_PASSPORT_PDQL,
)
from ..services.main_host import host
from ..services.mpvm_session import mpvm_session_connected
from .routers import system_router


@system_router.get("/api/health")
def health() -> dict[str, Any]:
    connected = mpvm_session_connected()
    state = host.CONTAINER.database_recovery.check()
    return {
        "ok": True,
        "app": "mpvm-rest-client",
        "database": db.database_label(),
        "database_ready": state["ready"],
        "database_error": state.get("reason"),
        "connected": connected,
        "api_url": host.SESSION.api_url,
        "background_workers": {
            "scan_postprocess": host.SCAN_POSTPROCESS_WORKERS,
            "scan_asset_process": host.SCAN_ASSET_PROCESS_WORKERS,
            "asset_card_requests": host.ASSET_CARD_REQUEST_WORKERS,
            "asset_card_refreshes": host.ASSET_CARD_REFRESH_WORKERS,
        },
    }


@system_router.get("/api/system/status")
def system_status() -> dict[str, Any]:
    checked_at = datetime.now(UTC).isoformat(timespec="seconds")
    readiness = host.CONTAINER.database_recovery.check()
    database_state = "ok" if readiness["database_ready"] else "down"
    database_error = None if readiness["ready"] else readiness.get("reason")
    host.DATABASE_STARTUP_ERROR = database_error
    circuit = db.database_circuit_status()
    connected = mpvm_session_connected()
    mpvm_state = "ok" if connected else "degraded"
    workers_state = "ok" if readiness["ready"] else "down"
    components = {
        "application": {"state": "ok", "message": "Приложение работает.", "retryable": False},
        "database": {
            "state": database_state,
            "message": "PostgreSQL доступен." if database_state == "ok" else "PostgreSQL недоступен.",
            "reason": database_error,
            "retryable": database_state != "ok",
            "circuit_breaker": circuit,
        },
        "mpvm": {
            "state": mpvm_state,
            "message": "Сессия MP VM активна." if connected else "Нет активной сессии MP VM.",
            "retryable": not connected,
            "api_url": host.SESSION.api_url,
        },
        "background_workers": {
            "state": workers_state,
            "message": "Фоновые исполнители готовы." if workers_state == "ok" else "Фоновые операции ожидают восстановления PostgreSQL.",
            "retryable": workers_state != "ok",
            "limits": {
                "scan_postprocess": host.SCAN_POSTPROCESS_WORKERS,
                "scan_asset_process": host.SCAN_ASSET_PROCESS_WORKERS,
                "asset_card_requests": host.ASSET_CARD_REQUEST_WORKERS,
                "asset_card_refreshes": host.ASSET_CARD_REFRESH_WORKERS,
                "passport_details": host.PASSPORT_DETAIL_WORKERS,
            },
        },
    }
    overall = "ok" if readiness["ready"] and connected else "degraded"
    return {"state": overall, "checked_at": checked_at, "components": components}


@system_router.get("/api/defaults")
def defaults() -> dict[str, Any]:
    return {
        "api_url": os.getenv("MPVM_API_URL") or os.getenv("MP10_API_URL") or "https://srv-siem.local",
        "client_id": os.getenv("MPVM_CLIENT_ID") or os.getenv("MP10_CLIENT_ID") or "mpx",
        "scope": os.getenv("MPVM_SCOPE") or os.getenv("MP10_SCOPE") or "authorization offline_access mpx.api ptkb.api",
        "utc_offset": os.getenv("MPVM_UTC_OFFSET") or os.getenv("MP10_UTC_OFFSET") or "+05:00",
        "software_vuln_pdql": SOFTWARE_VULN_PDQL,
        "vulnerability_passport_pdql": VULNER_PASSPORT_PDQL,
        "trending_vulnerability_pdql": TRENDING_VULNERABILITY_PDQL,
        "asset_card_pdql": ASSET_CARD_PDQL,
        "docker_vulnerability_pdql": DOCKER_VULNERABILITY_PDQL,
        "asset_card_refresh_workers": host.ASSET_CARD_REFRESH_WORKERS,
        "sample_csv_exists": host.SAMPLE_CSV.exists(),
    }
