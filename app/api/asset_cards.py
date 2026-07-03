from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, Response

from ..services import asset_card_reads


router = APIRouter(prefix="/api/asset-cards", tags=["asset-cards"])


def _finish(
    request: Request,
    response: Response,
    asset_id: str,
    section: str,
    payload: dict[str, Any] | None,
) -> dict[str, Any] | Response:
    if payload is None:
        raise HTTPException(status_code=404, detail="Asset card not found in local DB.")
    etag = asset_card_reads.etag_for(asset_id, str(payload.get("version") or ""), section)
    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag, "Cache-Control": "private, max-age=0, must-revalidate"})
    return payload


@router.get("/{asset_id}/overview", response_model=None)
def asset_card_overview(asset_id: str, request: Request, response: Response) -> dict[str, Any] | Response:
    return _finish(request, response, asset_id, "overview", asset_card_reads.get_overview(asset_id))


@router.get("/{asset_id}/configuration/tree", response_model=None)
def asset_card_tree(
    asset_id: str,
    request: Request,
    response: Response,
    parent_path: str | None = None,
    limit: int = Query(200, ge=1, le=500),
    cursor: str | None = None,
) -> dict[str, Any] | Response:
    try:
        offset = max(0, int(cursor or 0))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="cursor must be a non-negative integer") from exc
    payload = asset_card_reads.get_tree_children(
        asset_id,
        parent_path=parent_path,
        limit=limit,
        offset=offset,
    )
    return _finish(request, response, asset_id, f"tree:{parent_path or 'root'}:{offset}:{limit}", payload)


@router.get("/{asset_id}/configuration/detail", response_model=None)
def asset_card_configuration_detail(
    asset_id: str,
    request: Request,
    response: Response,
    path: str,
    kind: str,
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict[str, Any] | Response:
    payload = asset_card_reads.get_configuration_detail(
        asset_id,
        path=path,
        kind=kind,
        limit=limit,
        offset=offset,
    )
    return _finish(request, response, asset_id, f"detail:{kind}:{path}:{offset}:{limit}", payload)


@router.get("/{asset_id}/vulnerabilities/groups", response_model=None)
def asset_card_vulnerability_groups(asset_id: str, request: Request, response: Response) -> dict[str, Any] | Response:
    return _finish(request, response, asset_id, "vulnerability-groups", asset_card_reads.get_vulnerability_groups(asset_id))


@router.get("/{asset_id}/vulnerabilities/findings", response_model=None)
def asset_card_vulnerability_findings(
    asset_id: str,
    request: Request,
    response: Response,
    source: str,
    collection_id: str,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict[str, Any] | Response:
    payload = asset_card_reads.get_vulnerability_findings(
        asset_id,
        source=source,
        collection_id=collection_id,
        limit=limit,
        offset=offset,
    )
    return _finish(request, response, asset_id, f"findings:{source}:{collection_id}:{offset}:{limit}", payload)
