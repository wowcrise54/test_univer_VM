from __future__ import annotations

import logging
import sys

import uvicorn
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse

from . import __version__
from .client import AppClient
from .config import McpSettings
from .http_auth import HEALTH_PATH, BearerAuthMiddleware
from .server import build_server

logger = logging.getLogger("mpvm_mcp")


def main() -> int:
    # stdout belongs to the protocol in stdio mode, so all logging goes to stderr.
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        settings = McpSettings()
    except ValidationError as exc:
        for error in exc.errors():
            logger.error("Invalid configuration: %s", error["msg"])
        return 2

    server = build_server(settings, AppClient(settings))
    if settings.transport == "stdio":
        logger.info("mpvm-mcp %s: stdio, API %s", __version__, settings.api_url)
        server.run("stdio")
        return 0

    @server.custom_route(HEALTH_PATH, methods=["GET"])
    async def healthz(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "version": __version__})

    app = server.streamable_http_app(host=settings.host, stateless_http=True, json_response=True)
    if settings.auth_token:
        app.add_middleware(BearerAuthMiddleware, token=settings.auth_token)
    else:
        logger.warning("MPVM_MCP_AUTH_TOKEN is empty: the HTTP endpoint is unauthenticated (loopback only)")
    logger.info("mpvm-mcp %s: http://%s:%s/mcp, API %s", __version__, settings.host, settings.port, settings.api_url)
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
