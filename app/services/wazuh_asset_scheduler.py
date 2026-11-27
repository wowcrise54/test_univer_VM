"""Keep local Wazuh assessments up to date independently of card views."""

from concurrent.futures import Future
from datetime import UTC, datetime, timedelta
from threading import Event, Lock

from ..core.runtime import OperationRunner
from ..diagnostics import log_exception
from ..repositories.asset_cards import wazuh_match
from .wazuh_asset_match import reconcile_asset

POLL_SECONDS = 60
RECHECK_INTERVAL = timedelta(hours=1)
BATCH_SIZE = 50


def reconcile_due_assets(stop: Event) -> None:
    cutoff = datetime.now(UTC) - RECHECK_INTERVAL
    after = ""
    while not stop.is_set():
        asset_ids = wazuh_match.due_asset_ids(after, cutoff, BATCH_SIZE)
        if not asset_ids:
            return
        for asset_id in asset_ids:
            if stop.is_set():
                return
            try:
                reconcile_asset(asset_id, cutoff, stop)
            except Exception:
                log_exception("wazuh-cti", "wazuh.asset_assessment.failed", asset_id=asset_id)
        after = asset_ids[-1]


class WazuhAssetScheduler:
    def __init__(self, runner: OperationRunner) -> None:
        self._runner = runner
        self._lock = Lock()
        self._stop = Event()
        self._future: Future[None] | None = None

    def start(self) -> None:
        with self._lock:
            if self._future is not None and not self._future.done():
                return
            self._stop.clear()
            self._future = self._runner.submit("wazuh-asset-scheduler", self._loop)

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                reconcile_due_assets(self._stop)
            except Exception:
                log_exception("wazuh-cti", "wazuh.asset_scheduler.failed")
            self._stop.wait(POLL_SECONDS)
