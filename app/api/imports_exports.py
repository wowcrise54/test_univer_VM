from __future__ import annotations

from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Literal

import requests
from fastapi import File, HTTPException, UploadFile
from fastapi.responses import FileResponse, StreamingResponse

from .. import db
from ..mpvm.common import http_error
from ..mpvm_client import MpVmApiError
from ..reports.vulnerability import render_vulnerability_xlsx
from ..reports.vulnerability_csv import stream_vulnerability_report_csv
from ..services.main_host import host
from ..services.scanner_task_launch import remove_assets_after_export
from .routers import imports_router
from .schemas import (
    CsvTextImportRequest,
    PdqlExportRequest,
    VulnerabilityReportRequest,
    VulnerabilityXlsxReportRequest,
)


@imports_router.post("/api/exports/pdql")
def export_pdql(payload: PdqlExportRequest) -> dict[str, Any]:
    client, token = host.require_mpvm()
    try:
        pdql_token = client.create_pdql_token(
            token,
            payload.pdql,
            utc_offset=payload.utc_offset,
            selected_group_ids=payload.group_ids,
            include_nested_groups=payload.include_nested_groups,
            asset_ids=payload.asset_ids,
        )
        csv_text = client.fetch_csv(token, pdql_token)
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc

    filename = f"mpvm_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    output_path = host.EXPORTS_DIR / filename
    output_path.write_text(csv_text, encoding="utf-8-sig")

    import_result: dict[str, Any] | None = None
    run_id: int | None = None
    if payload.import_results:
        import_result = db.import_csv_text(
            csv_text,
            source="mpvm_pdql_export",
            pdql=payload.pdql,
            csv_filename=filename,
            delete_after_export=payload.delete_assets_after_export,
        )
        run_id = int(import_result["run_id"])

    removal_result: dict[str, Any] | None = None
    if payload.delete_assets_after_export:
        removal_result = remove_assets_after_export(
            client=client,
            token=token,
            csv_text=csv_text,
            import_run_id=run_id,
            utc_offset=payload.utc_offset,
            group_ids=payload.group_ids,
            include_nested_groups=payload.include_nested_groups,
            asset_ids=payload.asset_ids,
            timeout_minutes=payload.delete_timeout_minutes,
            poll_seconds=payload.delete_poll_seconds,
        )

    return {
        "pdql_token": pdql_token,
        "csv_filename": filename,
        "csv_path": str(output_path),
        "csv_bytes": output_path.stat().st_size,
        "import": import_result,
        "removal": removal_result,
    }


@imports_router.post("/api/import/csv-text")
def import_csv_text(payload: CsvTextImportRequest) -> dict[str, Any]:
    return db.import_csv_text(
        payload.csv_text,
        source=payload.source,
        pdql=payload.pdql,
        csv_filename=payload.csv_filename,
    )


@imports_router.post("/api/import/csv-file")
def import_csv_file(file: UploadFile = File(...)) -> dict[str, Any]:  # noqa: B008
    # Sync handler: FastAPI runs it in the threadpool, so the blocking import
    # no longer stalls the event loop for every other request.
    max_bytes = host.SETTINGS.import_max_upload_mb * 1024 * 1024
    content = file.file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail={"code": "IMPORT_TOO_LARGE", "message": f"Файл больше {host.SETTINGS.import_max_upload_mb} МБ.", "component": "imports"},
        )
    text = host.decode_csv_bytes(content)
    return db.import_csv_text(text, source="uploaded_csv", csv_filename=file.filename)


@imports_router.post("/api/import/sample")
def import_sample() -> dict[str, Any]:
    if not host.SAMPLE_CSV.exists():
        raise HTTPException(status_code=404, detail=f"Sample CSV not found: {host.SAMPLE_CSV}")
    return db.import_csv_text(
        host.SAMPLE_CSV.read_text(encoding="utf-8-sig"),
        source="sample_csv",
        csv_filename=host.SAMPLE_CSV.name,
    )


@imports_router.post("/api/reports/vulnerabilities/{report_type}/csv")
def export_vulnerability_report(
    report_type: Literal["os", "software", "docker"],
    payload: VulnerabilityReportRequest,
) -> StreamingResponse:
    rows = (
        db.iter_docker_vulnerability_report_rows(payload.asset_ids)
        if report_type == "docker"
        else db.iter_vulnerability_report_rows(report_type, payload.asset_ids)
    )
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    filename = f"host_{report_type}_vulnerabilities_{timestamp}.csv"
    return StreamingResponse(
        stream_vulnerability_report_csv(report_type, rows),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@imports_router.post("/api/reports/vulnerabilities/xlsx")
def export_vulnerability_xlsx(payload: VulnerabilityXlsxReportRequest) -> StreamingResponse:
    """Export one saved asset and its locally stored vulnerability findings."""
    asset = db.get_asset_card(payload.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Сохранённый актив не найден.")
    asset_ids = [payload.asset_id]
    content = render_vulnerability_xlsx(
        asset,
        db.iter_vulnerability_report_rows("os", asset_ids),
        db.iter_vulnerability_report_rows("software", asset_ids),
        db.iter_docker_vulnerability_report_rows(asset_ids),
    )
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    filename = f"asset_{payload.asset_id}_vulnerabilities_{timestamp}.xlsx"
    return StreamingResponse(
        BytesIO(content),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@imports_router.get("/api/exports/{filename}")
def download_export(filename: str) -> FileResponse:
    path = host.EXPORTS_DIR / Path(filename).name
    if not path.exists():
        raise HTTPException(status_code=404, detail="Export file not found")
    return FileResponse(path, media_type="text/csv", filename=path.name)
