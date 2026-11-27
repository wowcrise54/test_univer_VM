from __future__ import annotations

import requests

from app.mpvm.transport import build_retry_adapter
from app.mpvm_client import MpVmApiError, MpVmClient, compact_json_summary


def test_transport_retries_only_safe_reads():
    retry = build_retry_adapter().max_retries

    assert retry.total == 3
    assert retry.is_retry("GET", 503)
    assert retry.is_retry("HEAD", 503)
    assert not retry.is_retry("POST", 503)
    assert not retry.is_retry("PUT", 503)
    assert not retry.is_retry("DELETE", 503)


def test_remote_error_does_not_expose_tokens():
    response = requests.Response()
    response.status_code = 502
    response._content = b'{"error":"failed","access_token":"remote-secret"}'

    try:
        MpVmClient._raise_for_status(response, "load assets")
    except MpVmApiError as exc:
        assert "remote-secret" not in str(exc)
        assert "[REDACTED]" in str(exc)
    else:
        raise AssertionError("Expected remote API error")


def test_unexpected_payload_summary_redacts_nested_secrets():
    summary = compact_json_summary({"result": {"client_secret": "remote-secret"}})

    assert "remote-secret" not in summary
    assert "[REDACTED]" in summary


def test_plain_text_remote_error_redacts_bearer_token():
    response = requests.Response()
    response.status_code = 502
    response._content = b"upstream rejected Bearer remote-secret"

    summary = MpVmClient._response_summary(response)

    assert "remote-secret" not in summary
    assert summary == "non-JSON response"


def test_success_with_invalid_json_is_rejected_without_body_leak():
    response = requests.Response()
    response.status_code = 200
    response._content = b"Bearer remote-secret"
    client = MpVmClient.__new__(MpVmClient)

    try:
        client._json_response(response, "load assets")
    except MpVmApiError as exc:
        assert "remote-secret" not in str(exc)
        assert "Cannot parse JSON" in str(exc)
    else:
        raise AssertionError("Expected invalid JSON error")
