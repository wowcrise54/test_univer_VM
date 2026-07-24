from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from ..repositories.vulnerabilities import (
    VULNERABILITY_SEVERITIES,
    VULNERABILITY_TRENDS_RETENTION_DAYS,
    VULNERABILITY_TRENDS_SCOPE,
    VulnerabilityAnalyticsRepository,
)

TrendBucket = Literal["day", "week"]


def _as_utc(value: datetime | str) -> datetime:
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        parsed = value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _iso_utc(value: datetime | str) -> str:
    return _as_utc(value).isoformat()


def _bucket_floor(value: datetime, bucket: TrendBucket) -> datetime:
    floor = value.replace(hour=0, minute=0, second=0, microsecond=0)
    if bucket == "week":
        floor -= timedelta(days=floor.weekday())
    return floor


def _next_bucket(value: datetime, bucket: TrendBucket) -> datetime:
    return value + timedelta(days=1 if bucket == "day" else 7)


class VulnerabilityAnalyticsService:
    def __init__(self, repository: VulnerabilityAnalyticsRepository) -> None:
        self._repository = repository

    def summary(self, **filters: Any) -> dict[str, Any]:
        return self._repository.summary(**filters)

    def trending(self, *, limit: int = 20) -> dict[str, Any]:
        return self._repository.trending(limit=limit)

    def list(self, **filters: Any) -> dict[str, Any]:
        return self._repository.list(**filters)

    def hosts(self, **filters: Any) -> dict[str, Any]:
        return self._repository.hosts(**filters)

    def capture_snapshot(
        self,
        *,
        trigger_kind: str,
        trigger_id: str,
        captured_at: datetime | None = None,
    ) -> dict[str, Any]:
        return self._repository.capture_snapshot(
            trigger_kind=trigger_kind,
            trigger_id=trigger_id,
            captured_at=captured_at,
        )

    def ensure_baseline(self, *, captured_at: datetime | None = None) -> dict[str, Any]:
        return self._repository.ensure_baseline(captured_at=captured_at)

    def trends(
        self,
        *,
        from_at: datetime | None = None,
        to_at: datetime | None = None,
        bucket: TrendBucket = "day",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if bucket not in {"day", "week"}:
            raise ValueError("bucket must be 'day' or 'week'")
        end = _as_utc(to_at or now or datetime.now(UTC))
        start = _as_utc(from_at) if from_at is not None else end - timedelta(days=30)
        if end < start:
            raise ValueError("to must be greater than or equal to from")
        if end - start > timedelta(days=VULNERABILITY_TRENDS_RETENTION_DAYS):
            raise ValueError(
                f"Requested range exceeds the {VULNERABILITY_TRENDS_RETENTION_DAYS}-day retention window"
            )

        snapshots = self._repository.trend_snapshots(
            from_at=start,
            to_at=end,
            scope=VULNERABILITY_TRENDS_SCOPE,
        )
        ordered = sorted(snapshots, key=lambda item: (_as_utc(item["captured_at"]), int(item["id"])))
        rows: list[dict[str, Any]] = []
        index = 0
        latest: dict[str, Any] | None = None
        while index < len(ordered) and _as_utc(ordered[index]["captured_at"]) < start:
            latest = ordered[index]
            index += 1

        cursor = _bucket_floor(start, bucket)
        while cursor <= end:
            following = _next_bucket(cursor, bucket)
            updated_in_bucket = False
            while index < len(ordered):
                captured = _as_utc(ordered[index]["captured_at"])
                if captured > end or captured >= following:
                    break
                latest = ordered[index]
                index += 1
                updated_in_bucket = True

            if latest is not None:
                rows.append(
                    {
                        "bucket_start": cursor.isoformat(),
                        "snapshot_at": _iso_utc(latest["captured_at"]),
                        "carried_forward": not updated_in_bucket,
                        "totals": dict(latest["totals"]),
                        "by_severity": {
                            severity: dict(latest["by_severity"][severity])
                            for severity in VULNERABILITY_SEVERITIES
                        },
                        "coverage": dict(latest["coverage"]),
                    }
                )
            cursor = following

        return {
            "scope": VULNERABILITY_TRENDS_SCOPE,
            "from": start.isoformat(),
            "to": end.isoformat(),
            "bucket": bucket,
            "retention_days": VULNERABILITY_TRENDS_RETENTION_DAYS,
            "rows": rows,
        }
