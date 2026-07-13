from __future__ import annotations

from typing import Any

from ..repositories.risk import RiskRepository


class RiskService:
    def __init__(self, repository: RiskRepository) -> None:
        self.repository = repository

    def queue(self, **filters: Any) -> dict[str, Any]:
        return self.repository.queue(**filters)

    def summary(self) -> dict[str, Any]:
        return self.repository.summary()

    def set_contexts(self, asset_ids: list[str], values: dict[str, Any], actor: str | None) -> dict[str, Any]:
        return self.repository.set_contexts(asset_ids, values, actor)

    def import_contexts(self, csv_text: str, actor: str | None) -> dict[str, Any]:
        return self.repository.import_csv(csv_text, actor)

    def create_campaign(self, values: dict[str, Any], actor: str | None) -> dict[str, Any]:
        return self.repository.create_campaign(values, actor)

    def list_campaigns(self) -> dict[str, Any]:
        return self.repository.list_campaigns()

    def get_campaign(self, campaign_id: str) -> dict[str, Any] | None:
        return self.repository.get_campaign(campaign_id)

    def update_campaign(self, campaign_id: str, values: dict[str, Any], actor: str | None) -> dict[str, Any] | None:
        return self.repository.update_campaign(campaign_id, values, actor)

    def verification_targets(self, campaign_id: str, actor: str | None) -> dict[str, Any] | None:
        return self.repository.verification_targets(campaign_id, actor)
