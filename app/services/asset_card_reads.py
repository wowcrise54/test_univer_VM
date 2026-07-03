from __future__ import annotations

import hashlib
from typing import Any, Callable

from ..repositories import asset_cards


def etag_for(asset_id: str, version: str, section: str) -> str:
    digest = hashlib.sha256(f"{asset_id}:{version}:{section}".encode("utf-8")).hexdigest()[:24]
    return f'"{digest}"'


def read_or_none(reader: Callable[..., dict[str, Any] | None], *args: Any, **kwargs: Any) -> dict[str, Any] | None:
    return reader(*args, **kwargs)


get_overview = asset_cards.get_overview
get_tree_children = asset_cards.get_tree_children
get_configuration_detail = asset_cards.get_configuration_detail
get_vulnerability_groups = asset_cards.get_vulnerability_groups
get_vulnerability_findings = asset_cards.get_vulnerability_findings
