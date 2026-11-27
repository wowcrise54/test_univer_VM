"""Configuration and OAuth must fail closed before performing remote requests."""
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.domain.errors import DomainError
from app.mpvm.auth import resolve_access_token


@pytest.mark.parametrize("field", [
    "timeout", "background_request_limit", "asset_card_request_workers",
    "asset_card_refresh_workers", "scan_postprocess_workers", "scan_asset_process_workers",
    "scan_target_resolution_workers", "reconciliation_workers", "passport_detail_workers",
    "scan_asset_resolution_timeout_seconds", "scan_asset_resolution_poll_seconds",
    "scan_asset_removal_timeout_seconds", "scan_asset_removal_poll_seconds",
    "docker_dynamic_group_timeout_seconds", "docker_dynamic_group_retention_seconds",
    "automation_scheduler_poll_seconds", "coverage_stale_days", "auth_session_hours",
    "ldap_connect_timeout_seconds",
])
@pytest.mark.parametrize("value", [0, -1])
def test_worker_and_timeout_configuration_rejects_non_positive_values(field, value):
    with pytest.raises(ValidationError, match="greater than zero"):
        Settings(_env_file=None, **{field: value})
    assert getattr(Settings(_env_file=None, **{field: 1}), field) == 1


@pytest.mark.parametrize("field", ["passport_detail_ttl_hours", "asset_metadata_ttl_seconds", "docker_dynamic_group_iterations", "docker_dynamic_group_settle_seconds"])
def test_optional_delays_and_cache_ttls_accept_zero_but_reject_negative(field):
    assert getattr(Settings(_env_file=None, **{field: 0}), field) == 0
    with pytest.raises(ValidationError, match="must not be negative"):
        Settings(_env_file=None, **{field: -1})


@pytest.mark.parametrize("url", ["http://example.test", "ftp://example.test", "//example.test"])
def test_webhooks_require_https(url):
    with pytest.raises(ValidationError, match="HTTPS"):
        Settings(_env_file=None, automation_webhook_url=url)
    assert Settings(_env_file=None, automation_webhook_url="  https://example.test/hook  ").automation_webhook_url == "https://example.test/hook"
    assert Settings(_env_file=None, automation_webhook_url=" ").automation_webhook_url == ""


def test_bootstrap_password_strength_and_secret_repr():
    with pytest.raises(ValidationError, match="12 characters"):
        Settings(_env_file=None, bootstrap_admin_password="short")
    assert Settings(_env_file=None, bootstrap_admin_password="").bootstrap_admin_password == ""
    settings = Settings(_env_file=None, bootstrap_admin_password="fixture-secure-password", password="fixture-password", client_secret="fixture-client-secret", access_token="fixture-access-token")
    assert "fixture-" not in repr(settings)


def test_process_settings_are_cached_and_refresh_explicitly(monkeypatch):
    get_settings.cache_clear()
    try:
        monkeypatch.setenv("MPVM_TIMEOUT", "321")
        first = get_settings()
        monkeypatch.setenv("MPVM_TIMEOUT", "654")
        assert get_settings() is first and first.timeout == 321
        get_settings.cache_clear()
        assert get_settings().timeout == 654
    finally:
        get_settings.cache_clear()


def auth_config(**overrides):
    return SimpleNamespace(**{
        "access_token": "", "username": "fixture-user", "password": "fixture-password",
        "client_secret": "fixture-secret", "client_id": "mpx", "scope": "mpx.api",
        "token_url": "https://example.test/oauth", "timeout": 17, **overrides,
    })


@pytest.mark.parametrize("token, expected", [("Bearer fixture-token", "fixture-token"), (" bearer  fixture-token ", "fixture-token"), (" fixture-token ", "fixture-token")])
def test_supplied_token_does_not_trigger_password_grant(token, expected):
    session, parse = MagicMock(), MagicMock()
    assert resolve_access_token(auth_config(access_token=token), session, parse, RuntimeError) == expected
    session.post.assert_not_called()
    parse.assert_not_called()


def test_empty_token_and_missing_credentials_fail_before_network_access():
    session = MagicMock()
    with pytest.raises(RuntimeError, match="Bearer token is empty"):
        resolve_access_token(auth_config(access_token="  "), session, MagicMock(), RuntimeError)
    with pytest.raises(RuntimeError, match="username, password, client_secret"):
        resolve_access_token(auth_config(username="", password="", client_secret=""), session, MagicMock(), RuntimeError)
    session.post.assert_not_called()


def test_password_grant_uses_configured_timeout_and_returns_token():
    session = MagicMock()
    parse = MagicMock(return_value={"access_token": "fixture-oauth-token"})
    assert resolve_access_token(auth_config(), session, parse, RuntimeError) == "fixture-oauth-token"
    session.post.assert_called_once_with(
        "https://example.test/oauth", data={"username": "fixture-user", "password": "fixture-password",
        "client_id": "mpx", "client_secret": "fixture-secret", "grant_type": "password",
        "response_type": "code id_token", "scope": "mpx.api"}, timeout=17,
    )
    parse.assert_called_once_with(session.post.return_value, "get OAuth access token")


def test_missing_oauth_token_is_rejected():
    with pytest.raises(RuntimeError, match="does not contain access_token"):
        resolve_access_token(auth_config(), MagicMock(), MagicMock(return_value={}), RuntimeError)


def test_domain_error_preserves_human_message_and_independent_contexts():
    first = DomainError("FAILED", "Action failed", context={"operation_id": "one"})
    second = DomainError("FAILED", "Another failure")
    assert str(first) == "Action failed"
    assert first.context == {"operation_id": "one"} and second.context == {}
