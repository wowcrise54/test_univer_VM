from __future__ import annotations

from datetime import date
from typing import Any

from ..domain.compliance import ComplianceScope
from ..repositories.compliance import ComplianceDataset, ComplianceRepository


class ComplianceService:
    def __init__(self, repository: ComplianceRepository) -> None:
        self._repository = repository

    def summary(self, *, scope: ComplianceScope, assessment_date: date) -> dict[str, Any]:
        return self._repository.summary(scope=scope, assessment_date=assessment_date)

    def findings(self, **options: Any) -> dict[str, Any]:
        return self._repository.findings(**options)

    def stale_assets(self, **options: Any) -> dict[str, Any]:
        return self._repository.stale_assets(**options)

    def report_dataset(
        self,
        *,
        scope: ComplianceScope,
        assessment_date: date,
        asset_ids: list[str] | None = None,
    ) -> ComplianceDataset:
        return self._repository.dataset(
            scope=scope,
            assessment_date=assessment_date,
            asset_ids=asset_ids,
        )
