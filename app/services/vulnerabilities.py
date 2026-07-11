from __future__ import annotations

from typing import Any

from ..repositories.vulnerabilities import VulnerabilityAnalyticsRepository


class VulnerabilityAnalyticsService:
    def __init__(self, repository: VulnerabilityAnalyticsRepository) -> None:
        self._repository = repository

    def summary(self, **filters: Any) -> dict[str, Any]:
        return self._repository.summary(**filters)

    def list(self, **filters: Any) -> dict[str, Any]:
        return self._repository.list(**filters)

    def hosts(self, **filters: Any) -> dict[str, Any]:
        return self._repository.hosts(**filters)
