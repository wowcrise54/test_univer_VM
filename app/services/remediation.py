from __future__ import annotations

import builtins
from datetime import UTC, datetime
from typing import Any

from ..diagnostics import log_exception
from ..repositories.remediation import STATUSES, CoverageRepository, RemediationRepository


class RemediationService:
    def __init__(self, repository: RemediationRepository, *, stale_days: int, webhook_enabled: bool = False) -> None:
        self.repository = repository
        self.stale_days = stale_days
        self.webhook_enabled = webhook_enabled

    def list(self, **filters: Any) -> dict[str, Any]:
        return self.repository.list(**filters)

    def get(self, case_id: str) -> dict[str, Any] | None:
        return self.repository.get(case_id)

    def update(self, case_id: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        status = payload.get("status")
        if status == "resolved":
            raise ValueError("Resolved status is assigned only after a complete refresh confirms absence.")
        if status and status not in STATUSES:
            raise ValueError("Unsupported remediation status.")
        if status == "risk_accepted":
            if not str(payload.get("risk_reason") or "").strip() or not payload.get("risk_expires_at"):
                raise ValueError("Risk acceptance requires a reason and expiration date.")
            expires = datetime.fromisoformat(str(payload["risk_expires_at"]).replace("Z", "+00:00"))
            if expires.astimezone(UTC) <= datetime.now(UTC):
                raise ValueError("Risk acceptance expiration must be in the future.")
        elif status:
            payload = {**payload, "risk_reason": None, "risk_expires_at": None}
        changes = {key: payload.get(key) for key in ("status", "assignee", "due_at", "risk_reason", "risk_expires_at") if key in payload}
        return self.repository.update(
            case_id, changes, expected_version=int(payload["expected_version"]), comment=payload.get("comment")
        )

    def bulk_update(self, case_ids: builtins.list[str], payload: dict[str, Any]) -> dict[str, Any]:
        updated: builtins.list[dict[str, Any]] = []
        conflicts: builtins.list[str] = []
        for case_id in dict.fromkeys(case_ids):
            current = self.repository.get(case_id)
            if not current:
                continue
            try:
                item = self.update(case_id, {**payload, "expected_version": current["version"]})
                if item:
                    updated.append(item)
            except RuntimeError:
                conflicts.append(case_id)
        return {"updated": updated, "updated_count": len(updated), "conflicts": conflicts}

    def summary(self) -> dict[str, Any]:
        result = self.repository.summary()
        self.repository.ensure_daily_digest(webhook_enabled=self.webhook_enabled, summary=result)
        return result

    def policy(self) -> dict[str, Any]:
        return self.repository.policy()

    def update_policy(self, values: dict[str, int], *, apply_to_open: bool) -> dict[str, Any]:
        return self.repository.update_policy(values, apply_to_open=apply_to_open)

    def reconcile_asset(self, asset_id: str) -> dict[str, int]:
        try:
            return self.repository.reconcile_asset(asset_id, stale_days=self.stale_days)
        except Exception:
            log_exception("remediation", "case.reconcile.failed", asset_id=asset_id)
            return {"created": 0, "reopened": 0, "resolved": 0}

    def reconcile_all(self) -> dict[str, int]:
        totals = {"created": 0, "reopened": 0, "resolved": 0}
        for asset_id in self.repository.asset_ids():
            result = self.reconcile_asset(asset_id)
            for key in totals:
                totals[key] += result[key]
        return totals

    def ensure_daily_digest(self, *, webhook_enabled: bool) -> bool:
        return self.repository.ensure_daily_digest(webhook_enabled=webhook_enabled)


class CoverageService:
    def __init__(self, repository: CoverageRepository, *, stale_days: int) -> None:
        self.repository = repository
        self.stale_days = stale_days

    def summary(self) -> dict[str, Any]:
        return self.repository.summary(stale_days=self.stale_days)

    def list_assets(self, **filters: Any) -> dict[str, Any]:
        return self.repository.list_assets(stale_days=self.stale_days, **filters)
