from __future__ import annotations

import builtins
from typing import TYPE_CHECKING, Any

from ..repositories import RepositoryBundle
from .remediation import CoverageService, RemediationService
from .risk import RiskService
from .vm_workflows import VmWorkflowService
from .vulnerabilities import VulnerabilityAnalyticsService

if TYPE_CHECKING:
    from ..core.runtime import OperationRunner


class OperationsService:
    def __init__(self, repositories: RepositoryBundle) -> None:
        self._repository = repositories.operations

    def list(self, **filters: Any) -> dict[str, Any]:
        return self._repository.list(**filters)

    def summary(self) -> dict[str, Any]:
        return self._repository.summary()


class AssetsService:
    def __init__(self, repositories: RepositoryBundle) -> None:
        self._repositories = repositories

    def list_findings(self, **filters: Any) -> dict[str, Any]:
        return self._repositories.assets.list_findings(**filters)

    def summary(self) -> dict[str, Any]:
        return self._repositories.assets.summary()


class TasksService:
    def __init__(self, repositories: RepositoryBundle) -> None:
        self._repository = repositories.tasks

    def list(self) -> builtins.list[dict[str, Any]]:
        return self._repository.list()


class AssetCardsService:
    def __init__(self, repositories: RepositoryBundle) -> None:
        self._repository = repositories.asset_cards

    def list(self, **filters: Any) -> dict[str, Any]:
        return self._repository.list(**filters)

    def get(self, asset_id: str, *, section: str = "full") -> dict[str, Any] | None:
        return self._repository.get(asset_id, section=section)


class PassportsService:
    def __init__(self, repositories: RepositoryBundle) -> None:
        self._repository = repositories.passports

    def list(self, **filters: Any) -> dict[str, Any]:
        return self._repository.list(**filters)

    def get(self, passport_id: str) -> dict[str, Any] | None:
        return self._repository.get(passport_id)


class AssetQueryService:
    def __init__(self, repositories: RepositoryBundle) -> None:
        self._repository = repositories.asset_query

    def fields(self, **filters: Any) -> dict[str, Any]:
        return self._repository.fields(**filters)

    def query(self, query: dict[str, Any], **options: Any) -> dict[str, Any]:
        return self._repository.query(query, **options)


class ServiceBundle:
    def __init__(
        self,
        repositories: RepositoryBundle,
        *,
        operation_runner: OperationRunner,
        coverage_stale_days: int = 7,
        automation_webhook_enabled: bool = False,
    ) -> None:
        self.operations = OperationsService(repositories)
        self.assets = AssetsService(repositories)
        self.tasks = TasksService(repositories)
        self.asset_cards = AssetCardsService(repositories)
        self.passports = PassportsService(repositories)
        self.asset_query = AssetQueryService(repositories)
        self.vulnerabilities = VulnerabilityAnalyticsService(repositories.vulnerabilities)
        self.remediation = RemediationService(
            repositories.remediation,
            stale_days=coverage_stale_days,
            webhook_enabled=automation_webhook_enabled,
        )
        self.coverage = CoverageService(repositories.coverage, stale_days=coverage_stale_days)
        self.risk = RiskService(repositories.risk)
        self.vm_workflows = VmWorkflowService(
            repositories.vm_workflows, operation_runner, self.remediation,
            coverage=self.coverage, risk=self.risk,
        )
