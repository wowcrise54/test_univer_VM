from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DomainError(RuntimeError):
    code: str
    message: str
    component: str = "application"
    status_code: int = 400
    retryable: bool = False
    context: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return self.message
