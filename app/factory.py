from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles

Lifespan = Callable[[FastAPI], AbstractAsyncContextManager[None]]


def create_app(*, static_dir: Path, lifespan: Lifespan | None = None) -> FastAPI:
    app = FastAPI(
        title="MP VM REST API Client",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Trace-ID", "X-Request-ID", "Server-Timing", "ETag"],
    )
    app.add_middleware(GZipMiddleware, minimum_size=1024)
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    return app
