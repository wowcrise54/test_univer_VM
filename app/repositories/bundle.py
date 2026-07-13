from __future__ import annotations

import builtins
from typing import Any

from .. import db
from .remediation import CoverageRepository, RemediationRepository
from .vulnerabilities import VulnerabilityAnalyticsRepository


class OperationsRepository:
    def list(self, **filters: Any) -> dict[str, Any]:
        return db.list_operations(**filters, sync_sources=True)

    def summary(self) -> dict[str, Any]:
        return db.get_operations_summary(sync_sources=True)

    def get(self, operation_id: str) -> dict[str, Any] | None:
        return db.get_operation(operation_id, sync_sources=True)

    def saved_views(self, route: str) -> builtins.list[dict[str, Any]]:
        return db.list_saved_views(route)


class TasksRepository:
    def list(self) -> builtins.list[dict[str, Any]]:
        return db.list_scan_tasks()

    def get(self, task_id: str) -> dict[str, Any] | None:
        return db.get_scan_task(task_id)


class AssetsRepository:
    def summary(self) -> dict[str, Any]:
        return db.get_summary()

    def list_findings(self, **filters: Any) -> dict[str, Any]:
        return db.list_asset_findings(**filters)


class AssetCardsRepository:
    def get(self, asset_id: str, *, section: str = "full") -> dict[str, Any] | None:
        if section == "full":
            return db.get_asset_card(asset_id)
        return db.get_asset_card_section(asset_id, section)

    def list(self, **filters: Any) -> dict[str, Any]:
        return db.list_asset_cards(**filters)


class PassportsRepository:
    def get(self, passport_id: str) -> dict[str, Any] | None:
        return db.get_vulnerability_passport(passport_id)

    def list(self, **filters: Any) -> dict[str, Any]:
        return db.list_vulnerability_passports(**filters)


class ImportsRepository:
    def import_csv(self, csv_text: str, **metadata: Any) -> dict[str, Any]:
        return db.import_csv_text(csv_text, **metadata)


class AssetQueryRepository:
    def fields(self, **filters: Any) -> dict[str, Any]:
        return db.list_asset_card_search_fields(**filters)

    def query(self, query: dict[str, Any], **options: Any) -> dict[str, Any]:
        return db.query_asset_cards_by_fields(query, **options)


class RepositoryBundle:
    def __init__(self) -> None:
        self.operations = OperationsRepository()
        self.tasks = TasksRepository()
        self.assets = AssetsRepository()
        self.asset_cards = AssetCardsRepository()
        self.passports = PassportsRepository()
        self.imports = ImportsRepository()
        self.asset_query = AssetQueryRepository()
        self.vulnerabilities = VulnerabilityAnalyticsRepository()
        self.remediation = RemediationRepository()
        self.coverage = CoverageRepository()
