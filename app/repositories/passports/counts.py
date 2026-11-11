"""In-process memo of passport list totals, invalidated on every catalog write.

The list total depends only on which rows match the filter, and rows change
only through the write paths in this package (catalog upsert/delete, detail
upserts, trends replacement). Each write path calls
:func:`invalidate_passport_totals` after its transaction commits, so a cached
total can never outlive a write — there is no TTL and no cross-process state
(the app runs a single uvicorn process without workers).

The memo is bounded: more distinct filters than :data:`_MAX_ENTRIES` clears
it, which is safe because a miss only costs one re-computed ``COUNT(*)``.
"""

from __future__ import annotations

from threading import Lock

_MAX_ENTRIES = 512

_lock = Lock()
_totals: dict[tuple[str, str, str], int] = {}


def passport_total_key(
    q: str | None,
    severity: str | None,
    pdql_token: str | None,
) -> tuple[str, str, str]:
    """Cache key for the list filters (q and severity are matched case-insensitively)."""
    return (
        q.casefold() if q else "",
        severity.casefold() if severity else "",
        pdql_token or "",
    )


def cached_passport_total(key: tuple[str, str, str]) -> int | None:
    with _lock:
        return _totals.get(key)


def remember_passport_total(key: tuple[str, str, str], total: int) -> None:
    with _lock:
        if key not in _totals and len(_totals) >= _MAX_ENTRIES:
            _totals.clear()
        _totals[key] = total


def invalidate_passport_totals() -> None:
    """Drop every cached total; call after any committed write to ``vulnerability_passports``."""
    with _lock:
        _totals.clear()
