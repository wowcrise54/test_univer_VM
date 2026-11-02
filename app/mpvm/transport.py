from __future__ import annotations

import logging
import threading
import warnings

from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util import Retry

from ..diagnostics import DiagnosticSession, log_event

_TLS_WARNING_LOCK = threading.Lock()
_TLS_WARNING_LOGGED = False


def _note_tls_verification_disabled() -> None:
    """Replace urllib3's per-request warning with one structured log record.

    Disabled verification is a deliberate setting (MPVM_VERIFY_TLS=false), so a
    warning on every request only buries real problems in the console.
    """
    global _TLS_WARNING_LOGGED
    warnings.filterwarnings("ignore", category=InsecureRequestWarning)
    with _TLS_WARNING_LOCK:
        if _TLS_WARNING_LOGGED:
            return
        _TLS_WARNING_LOGGED = True
    log_event(
        "mpvm-http",
        "tls.verification.disabled",
        level=logging.WARNING,
        hint="Set MPVM_VERIFY_TLS=true and trust the MP VM CA to enable verification",
    )


def build_retry_adapter() -> HTTPAdapter:
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        status=3,
        backoff_factor=0.8,
        status_forcelist=(429, 500, 502, 503, 504),
        # A status/read retry may replay a request after MP VM has already
        # applied it. Mutations are retried only by the workflow layer, where
        # an idempotency key and persisted progress are available.
        allowed_methods=("GET", "HEAD", "OPTIONS"),
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    return HTTPAdapter(max_retries=retry)


def build_session(*, verify_tls: bool) -> DiagnosticSession:
    session = DiagnosticSession()
    session.verify = verify_tls
    if not verify_tls:
        _note_tls_verification_disabled()
    session.headers.update({"User-Agent": "mp-vm-rest-client/1.0"})
    session.mount("https://", build_retry_adapter())
    session.mount("http://", build_retry_adapter())
    return session
