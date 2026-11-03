from __future__ import annotations

import json
from typing import Any


def _size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, default=str))


def fit_response(data: Any, max_chars: int) -> dict[str, Any]:
    """Return ``data`` as a dict no larger than ``max_chars`` when serialized.

    Lists are halved (largest first) until the answer fits, and the result is
    flagged ``truncated`` so the model knows the answer is partial.
    """
    result: dict[str, Any] = data if isinstance(data, dict) else {"rows": data}
    if _size(result) <= max_chars:
        return result
    result = dict(result)
    result["truncated"] = True
    for _ in range(40):
        if _size(result) <= max_chars:
            break
        candidates = [(key, value) for key, value in result.items() if isinstance(value, list) and len(value) > 1]
        if not candidates:
            break
        key, value = max(candidates, key=lambda item: _size(item[1]))
        result[key] = value[: max(1, len(value) // 2)]
        result["truncated_note"] = "The answer was shortened to fit the size limit; narrow the query or page with offset."
    return result
