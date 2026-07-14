from __future__ import annotations

import threading
from dataclasses import dataclass

from ..mpvm_client import MpVmClient
from ..repositories import RepositoryBundle
from ..services import ServiceBundle
from .config import Settings
from .runtime import OperationRunner


@dataclass
class RuntimeSession:
    client: MpVmClient | None = None
    access_token: str | None = None
    api_url: str | None = None
    token_url: str | None = None
    username: str | None = None
    verify_tls: bool = True


class AppContainer:
    """Explicit owner of mutable process-scoped application state."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.session = RuntimeSession()
        self.repositories = RepositoryBundle()
        self.operation_runner = OperationRunner(
            {
                "scan-postprocess": settings.scan_postprocess_workers,
                "vm-workflow": 4,
                "automation-run": 2,
                "automation-scheduler": 1,
            }
        )
        self.services = ServiceBundle(
            self.repositories,
            coverage_stale_days=settings.coverage_stale_days,
            automation_webhook_enabled=bool(settings.automation_webhook_url),
            operation_runner=self.operation_runner,
        )
        self.background_request_semaphore = threading.BoundedSemaphore(settings.background_request_limit)
        self.asset_metadata_cache: dict[tuple[str, str], tuple[float, dict]] = {}
        self.asset_metadata_inflight: dict[tuple[str, str], threading.Event] = {}
        self.asset_metadata_cache_lock = threading.Lock()

    def start(self) -> None:
        self.operation_runner.start()

    def shutdown(self) -> None:
        self.operation_runner.shutdown(wait=False)
