from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime

import psycopg

from .. import db
from .main_host import host


def start_asset_search_backfill(*, strict: bool = False) -> None:
    with host.ASSET_SEARCH_BACKFILL_LOCK:
        if host.ASSET_SEARCH_BACKFILL_RUNNING:
            return
        try:
            coverage = db.asset_card_search_index_coverage()
        except psycopg.Error:
            if strict:
                raise
            return
        if (
            coverage["indexed_cards"] >= coverage["total_cards"]
            and coverage["software_inventory_indexed_cards"]
            >= coverage["software_inventory_total_cards"]
        ):
            return
        host.ASSET_SEARCH_BACKFILL_RUNNING = True
    thread = threading.Thread(target=run_asset_search_backfill, daemon=True, name="asset-search-backfill")
    thread.start()


def run_asset_search_backfill() -> None:
    operation_id = str(uuid.uuid4())
    try:
        coverage = db.asset_card_search_index_coverage()
        total = max(coverage["total_cards"], coverage["software_inventory_total_cards"], 1)
        indexed = min(
            coverage["indexed_cards"],
            coverage["software_inventory_indexed_cards"],
        )
        db.register_operation(
            operation_id,
            kind="asset_search_reindex",
            source_id=operation_id,
            status="running",
            stage="indexing",
            progress_percent=round(indexed * 100 / total),
            subject_type="asset_cards",
            subject_label="Индексы карточек активов",
            message="Индексы полей и ПО существующих карточек активов.",
        )
        while True:
            search_done = coverage["indexed_cards"] >= coverage["total_cards"]
            software_done = (
                coverage["software_inventory_indexed_cards"]
                >= coverage["software_inventory_total_cards"]
            )
            if search_done and software_done:
                break
            if not search_done:
                batch = db.backfill_asset_card_search_index_batch(limit=20)
            else:
                batch = db.backfill_asset_card_software_inventory_batch(limit=20)
            if not batch["processed"]:
                break
            coverage = db.asset_card_search_index_coverage()
            indexed = min(
                coverage["indexed_cards"],
                coverage["software_inventory_indexed_cards"],
            )
            db.register_operation(
                operation_id,
                kind="asset_search_reindex",
                source_id=operation_id,
                status="running",
                stage="indexing",
                progress_percent=round(indexed * 100 / total),
                subject_type="asset_cards",
                subject_label="Индексы карточек активов",
                message=(
                    "Индексы: "
                    f"поля {coverage['indexed_cards']}/{coverage['total_cards']}, "
                    "ПО "
                    f"{coverage['software_inventory_indexed_cards']}/"
                    f"{coverage['software_inventory_total_cards']}."
                ),
                result=coverage,
            )
        final_status = (
            "completed"
            if coverage["indexed_cards"] >= coverage["total_cards"]
            and coverage["software_inventory_indexed_cards"]
            >= coverage["software_inventory_total_cards"]
            else "completed_with_errors"
        )
        db.register_operation(
            operation_id,
            kind="asset_search_reindex",
            source_id=operation_id,
            status=final_status,
            stage=final_status,
            progress_percent=100,
            subject_type="asset_cards",
            subject_label="Индексы карточек активов",
            message=(
                "Индексация завершена: "
                f"поля {coverage['indexed_cards']}/{coverage['total_cards']}, "
                "ПО "
                f"{coverage['software_inventory_indexed_cards']}/"
                f"{coverage['software_inventory_total_cards']}."
            ),
            result=coverage,
            finished_at=datetime.now(UTC).isoformat(timespec="seconds"),
        )
    except Exception as exc:
        host.log_exception("app", "asset_search.backfill.failed", operation_id=operation_id)
        try:
            db.register_operation(
                operation_id,
                kind="asset_search_reindex",
                source_id=operation_id,
                status="failed",
                stage="failed",
                subject_type="asset_cards",
                subject_label="Индекс полей карточек активов",
                message="Не удалось завершить индексацию карточек.",
                error={"message": str(exc)[:1000]},
                finished_at=datetime.now(UTC).isoformat(timespec="seconds"),
            )
        except Exception:
            pass
    finally:
        with host.ASSET_SEARCH_BACKFILL_LOCK:
            host.ASSET_SEARCH_BACKFILL_RUNNING = False
