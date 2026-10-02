from __future__ import annotations

from typing import Annotated

import requests
from fastapi import APIRouter, HTTPException, Query, Request

from app.mpvm_client import MpVmApiError

router = APIRouter(prefix="/api/scanner-tasks", tags=["scanner-tasks"])


def _task_runtime(request: Request, task_id: str):
    container = request.app.state.container
    if not container.services.tasks.get(task_id):
        raise HTTPException(404, detail="Local scanner task not found.")
    session = container.session
    if not session.client or not session.access_token:
        raise HTTPException(409, detail="MP VM connection is not configured. Connect first.")
    return session.client, session.access_token


@router.get("/{task_id}/runs")
def scanner_task_runs(
    request: Request,
    task_id: str,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> dict:
    client, token = _task_runtime(request, task_id)
    try:
        items = client.get_task_runs(token, task_id, offset=offset, limit=limit)
    except (MpVmApiError, requests.RequestException) as exc:
        raise HTTPException(502, detail="Could not load scanner task runs from MP VM.") from exc
    return {"items": items, "total": len(items), "offset": offset, "limit": limit, "has_more": len(items) == limit}


@router.get("/{task_id}/runs/{run_id}/jobs")
def scanner_task_run_jobs(request: Request, task_id: str, run_id: str) -> dict:
    client, token = _task_runtime(request, task_id)
    try:
        offset = 0
        page_size = 100
        belongs_to_task = False
        while offset < 10000:
            runs = client.get_task_runs(token, task_id, offset=offset, limit=page_size)
            if any(str(item.get("id") or "") == run_id for item in runs):
                belongs_to_task = True
                break
            if len(runs) < page_size:
                break
            offset += len(runs)
        if not belongs_to_task:
            raise HTTPException(404, detail="Scanner run not found for this task.")
        jobs = client.get_all_run_jobs(token, run_id, target_pattern="", orderby="startedAt desc", batch_size=1000)
    except HTTPException:
        raise
    except (MpVmApiError, requests.RequestException) as exc:
        raise HTTPException(502, detail="Could not load scanner run jobs from MP VM.") from exc
    return {"items": jobs, "total": len(jobs)}
