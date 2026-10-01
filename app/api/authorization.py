from __future__ import annotations

from typing import Any

from starlette.requests import Request
from starlette.routing import Match

from .permissions import ROUTE_PERMISSIONS


def request_permission(request: Request) -> str:
    """Authorize the selected route, including lazy/prefixed FastAPI routers.

    Resolving the real route prevents a newly registered static endpoint from
    accidentally inheriting the permission of a neighbouring /{identifier}.
    Schema visibility is irrelevant: hidden routes must have a policy too.
    """
    scope = dict(request.scope)
    method = request.method
    scope["method"] = method
    for route in request.app.routes:
        contexts = getattr(route, "effective_route_contexts", None)
        candidates: Any = contexts() if callable(contexts) else (route,)
        for candidate in candidates:
            match, _ = candidate.matches(scope)
            if match == Match.FULL:
                path = getattr(candidate, "path_format", None) or getattr(candidate, "path", "")
                policy_method = "GET" if method == "HEAD" and "GET" in candidate.methods else method
                return ROUTE_PERMISSIONS.get((policy_method, str(path)), "__deny__")
    return "__deny__"
