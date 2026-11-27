from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException
from fastapi.responses import Response, StreamingResponse

from .. import db
from ..services.main_host import host
from .routers import asset_query_router
from .schemas import AssetCardFieldQueryRequest, AssetCardPresetQueryRequest


@asset_query_router.get("/api/asset-card-query/fields")
def asset_card_query_fields(q: str | None = None, limit: int = 100) -> dict[str, Any]:
    host.start_asset_search_backfill()
    return host.CONTAINER.services.asset_query.fields(q=q, limit=limit)


@asset_query_router.get("/api/asset-card-query/presets")
def asset_card_query_presets() -> dict[str, Any]:
    return {
        "rows": db.list_asset_card_query_presets(),
        "execution": "local",
        "source": "asset_cards",
    }


@asset_query_router.post("/api/asset-card-query/presets/{preset_id}")
def execute_asset_card_query_preset(
    preset_id: str,
    payload: AssetCardPresetQueryRequest,
) -> dict[str, Any]:
    host.start_asset_search_backfill()
    try:
        return db.query_asset_card_preset(
            preset_id,
            software_name=payload.software_name,
            software_version_like=payload.software_version_like,
            vendor=payload.vendor,
            os_name=payload.os_name,
            os_version_like=payload.os_version_like,
            limit=payload.limit,
            offset=payload.offset,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "ASSET_QUERY_PRESET_NOT_FOUND",
                "message": f"Unknown asset query preset: {preset_id}",
                "component": "asset_cards",
            },
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "INVALID_ASSET_QUERY_PRESET",
                "message": str(exc),
                "component": "asset_cards",
            },
        ) from exc


@asset_query_router.post("/api/asset-card-query/presets/{preset_id}/assets")
def execute_asset_card_query_preset_assets(
    preset_id: str,
    payload: AssetCardPresetQueryRequest,
) -> dict[str, Any]:
    host.start_asset_search_backfill()
    try:
        return db.query_asset_card_preset_assets(
            preset_id,
            software_name=payload.software_name,
            software_version=payload.software_version,
            vendor=payload.vendor,
            os_name=payload.os_name,
            os_version=payload.os_version,
            limit=payload.limit,
            offset=payload.offset,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "ASSET_QUERY_PRESET_NOT_FOUND",
                "message": f"Unknown asset query preset: {preset_id}",
                "component": "asset_cards",
            },
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "INVALID_ASSET_QUERY_PRESET_ASSETS",
                "message": str(exc),
                "component": "asset_cards",
            },
        ) from exc


@asset_query_router.post("/api/asset-card-query")
def asset_card_query(payload: AssetCardFieldQueryRequest) -> dict[str, Any]:
    host.start_asset_search_backfill()
    try:
        return host.CONTAINER.services.asset_query.query(
            payload.query,
            sort_by=payload.sort_by,
            sort_dir=payload.sort_dir,
            limit=payload.limit,
            offset=payload.offset,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_ASSET_QUERY", "message": str(exc), "component": "asset_cards"},
        ) from exc


@asset_query_router.post("/api/asset-card-query/export")
def export_asset_card_query(payload: AssetCardFieldQueryRequest) -> Response:
    try:
        first_page = db.query_asset_cards_by_fields(
            payload.query,
            sort_by=payload.sort_by,
            sort_dir=payload.sort_dir,
            limit=5000,
            offset=0,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_ASSET_QUERY", "message": str(exc), "component": "asset_cards"},
        ) from exc
    def stream_rows():
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(["asset_id", "display_name", "ip_address", "fqdn", "os_name", "last_seen", "entity_path", "field_path", "value"])
        yield "\ufeff" + output.getvalue()
        page = first_page
        offset = 0
        while True:
            for card in page["rows"]:
                matches = card.get("matches") or [{}]
                for match in matches:
                    output.seek(0)
                    output.truncate(0)
                    writer.writerow([
                        card.get("asset_id"), card.get("display_name"), card.get("ip_address"), card.get("fqdn"),
                        card.get("os_name"), card.get("last_seen"), match.get("entity_path"),
                        match.get("field_path"), match.get("value"),
                    ])
                    yield output.getvalue()
            offset += len(page["rows"])
            if not page["rows"] or offset >= page["total"]:
                break
            page = db.query_asset_cards_by_fields(
                payload.query,
                sort_by=payload.sort_by,
                sort_dir=payload.sort_dir,
                limit=5000,
                offset=offset,
            )
    filename = f"asset-query-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}.csv"
    return StreamingResponse(
        stream_rows(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
