from __future__ import annotations

from typing import Any

from ..repositories.attention import AttentionRepository


class AttentionService:
    def __init__(self, repository: AttentionRepository) -> None:
        self.repository = repository

    def attention(self, **kwargs: Any) -> dict[str, Any]:
        return self.repository.attention(**kwargs)

    def search(self, **kwargs: Any) -> dict[str, Any]:
        return self.repository.search(**kwargs)
