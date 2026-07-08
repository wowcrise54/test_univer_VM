from __future__ import annotations

from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from ..diagnostics import DiagnosticSession


def build_retry_adapter() -> HTTPAdapter:
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        status=3,
        backoff_factor=0.8,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "POST", "PUT", "DELETE"),
    )
    return HTTPAdapter(max_retries=retry)


def build_session(*, verify_tls: bool) -> DiagnosticSession:
    session = DiagnosticSession()
    session.verify = verify_tls
    session.headers.update({"User-Agent": "mp-vm-rest-client/1.0"})
    session.mount("https://", build_retry_adapter())
    session.mount("http://", build_retry_adapter())
    return session
