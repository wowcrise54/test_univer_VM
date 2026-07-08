from __future__ import annotations

from collections.abc import Callable
from typing import Any

import requests


def resolve_access_token(
    auth: Any,
    session: requests.Session,
    parse_response: Callable[[requests.Response, str], dict[str, Any]],
    error_type: type[RuntimeError],
) -> str:
    """Resolve a supplied bearer token or perform the OAuth password grant."""

    if auth.access_token:
        access_token = auth.access_token.strip()
        if access_token.lower().startswith("bearer "):
            access_token = access_token[7:].strip()
        if not access_token:
            raise error_type("Bearer token is empty.")
        return access_token

    required = {
        "username": auth.username,
        "password": auth.password,
        "client_secret": auth.client_secret,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise error_type("Missing authentication fields: " + ", ".join(missing))

    response = session.post(
        auth.token_url,
        data={
            "username": auth.username,
            "password": auth.password,
            "client_id": auth.client_id,
            "client_secret": auth.client_secret,
            "grant_type": "password",
            "response_type": "code id_token",
            "scope": auth.scope,
        },
        timeout=auth.timeout,
    )
    data = parse_response(response, "get OAuth access token")
    token = data.get("access_token")
    if not token:
        raise error_type("OAuth response does not contain access_token.")
    return str(token)
