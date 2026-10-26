from __future__ import annotations

from collections.abc import Callable, Sequence
from contextlib import AbstractAsyncContextManager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles

Lifespan = Callable[[FastAPI], AbstractAsyncContextManager[None]]

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
}


def create_app(
    *,
    static_dir: Path,
    lifespan: Lifespan | None = None,
    cors_origins: Sequence[str] = (),
) -> FastAPI:
    app = FastAPI(
        title="MP VM REST API Client",
        version="0.1.0",
        lifespan=lifespan,
    )
    # The SPA is served from the same origin (Vite proxies /api in dev), so CORS
    # is opt-in. A wildcard together with credentials would let any page that
    # receives the session cookie read the API on the user's behalf.
    origins = [origin for origin in cors_origins if origin and origin != "*"]
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
            expose_headers=["X-Trace-ID", "X-Request-ID", "Server-Timing", "ETag"],
        )
    app.add_middleware(GZipMiddleware, minimum_size=1024)

    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    return app
