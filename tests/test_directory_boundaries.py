"""Directory boundary failures use mocked LDAP transports, never a live directory."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from app import auth, ldap


@pytest.fixture
def settings():
    return SimpleNamespace(
        ldap_enabled=True,
        ldap_url="ldaps://directory.example",
        ldap_base_dn="DC=example",
        ldap_bind_dn="CN=lookup,DC=example",
        ldap_bind_password="fixture-only",
        ldap_user_filter="(uid={username})",
        ldap_display_name_attribute="preferredName",
        ldap_connect_timeout_seconds=7,
        ldap_required_ou="",
        ldap_admin_group_dn="",
        ldap_default_role="viewer",
    )


def test_user_filter_escapes_ldap_metacharacters(settings):
    assert ldap._filter_for("a*)(uid=*)\x00\\", settings) == r"(uid=a\2a\29\28uid=\2a\29\00\5c)"


@pytest.mark.parametrize(
    "dn,required,allowed",
    [
        ("CN=user,OU=Allowed,DC=example", "", True),
        ("CN=user,OU=allowed_TEAM,DC=example", "Allowed", True),
        ("CN=user,OU=Other,DC=example", "Allowed", False),
        ("OU=Allowed,DC=example", "Allowed", True),
        ("CN=user,OU=Allowed.other,DC=example", "Allowed", False),
    ],
)
def test_ou_restriction_matches_components_and_supported_team_suffixes(settings, dn, required, allowed):
    settings.ldap_required_ou = required
    assert ldap._is_in_required_ou(dn, settings) is allowed


@pytest.mark.parametrize(
    "url", ["https://directory.example", "ldap:///", "ldaps://directory.example:bad", "ldaps://[bad"]
)
def test_malformed_directory_urls_fail_before_opening_a_connection(monkeypatch, settings, url):
    server = MagicMock()
    monkeypatch.setattr("ldap3.Server", server)
    settings.ldap_url = url
    with pytest.raises(ldap.LdapError, match="invalid_ldap_url"):
        ldap._build_connection(settings)
    server.assert_not_called()


@pytest.mark.parametrize(
    "url,port,tls", [("ldap://directory.example", 389, False), ("ldaps://directory.example:1636", 1636, True)]
)
def test_directory_transport_preserves_port_clamps_timeout_and_supports_anonymous_lookup(
    monkeypatch, settings, url, port, tls
):
    settings.ldap_url = url
    settings.ldap_connect_timeout_seconds = 0
    server, connection = MagicMock(), MagicMock()
    monkeypatch.setattr("ldap3.Server", server)
    monkeypatch.setattr("ldap3.Connection", connection)
    assert ldap._build_connection(settings) is connection.return_value
    assert server.call_args.kwargs["port"] == port and server.call_args.kwargs["use_ssl"] is tls
    assert server.call_args.kwargs["connect_timeout"] == 1
    assert connection.call_args.kwargs == {"user": None, "password": None, "auto_bind": True, "read_only": True}


@pytest.mark.parametrize("kind", ["anonymous", "lookup", "user"])
def test_bind_failures_are_normalized_and_identify_the_account_kind(monkeypatch, settings, kind, caplog):
    monkeypatch.setattr("ldap3.Server", MagicMock())
    monkeypatch.setattr("ldap3.Connection", MagicMock(side_effect=RuntimeError()))
    user = {"anonymous": None, "lookup": settings.ldap_bind_dn, "user": "CN=user,DC=example"}[kind]
    with pytest.raises(ldap.LdapError, match="ldap_bind_failed"):
        ldap._build_connection(settings, user, "fixture-password-must-not-appear")
    assert f"{kind} account" in caplog.text
    assert "fixture-password-must-not-appear" not in caplog.text


class Entry(dict):
    entry_dn = "CN=Fixture,DC=example"


@pytest.mark.parametrize(
    "attributes,expected",
    [
        ({"preferredName": "Preferred"}, "Preferred"),
        ({"displayName": "Display"}, "Display"),
        ({"cn": "Common"}, "Common"),
        ({}, ""),
    ],
)
def test_directory_search_copies_entries_and_uses_display_name_fallbacks(monkeypatch, settings, attributes, expected):
    connection = MagicMock()
    connection.entries = [Entry(attributes)]
    connection.unbind.side_effect = lambda: connection.entries.clear()
    monkeypatch.setattr(ldap, "_build_connection", lambda *args: connection)
    assert ldap._search_user(settings, "fixture") == {"dn": "CN=Fixture,DC=example", "display": expected}
    connection.search.assert_called_once_with(
        "DC=example", "(uid=fixture)", size_limit=2, attributes=["preferredName", "displayName", "cn"]
    )
    connection.unbind.assert_called_once()


@pytest.mark.parametrize("matches", [0, 2])
def test_directory_search_handles_missing_or_ambiguous_users_and_always_unbinds(monkeypatch, settings, matches, caplog):
    connection = MagicMock()
    connection.entries = [Entry({"cn": "First"})] * matches
    monkeypatch.setattr(ldap, "_build_connection", lambda *args: connection)
    result = ldap._search_user(settings, "fixture")
    assert result == ({"dn": "CN=Fixture,DC=example", "display": "First"} if matches else None)
    connection.unbind.assert_called_once()
    if matches:
        assert "используется первая" in caplog.text


@pytest.mark.parametrize("method", ["_search_user", "_in_admin_group"])
def test_search_failure_reports_a_directory_error_and_closes_the_connection(monkeypatch, settings, method):
    settings.ldap_admin_group_dn = "CN=Admins,DC=example"
    connection = MagicMock()
    connection.search.return_value = False
    connection.result = {}
    monkeypatch.setattr(ldap, "_build_connection", lambda *args: connection)
    with pytest.raises(ldap.LdapError, match="unknown"):
        getattr(ldap, method)(settings, "fixture")
    connection.unbind.assert_called_once()


@pytest.mark.parametrize("member", [False, True])
def test_admin_group_membership_escapes_the_user_dn_and_unbinds(monkeypatch, settings, member):
    connection = MagicMock()
    connection.entries = [Entry()] if member else []
    monkeypatch.setattr(ldap, "_build_connection", lambda *args: connection)
    assert ldap._in_admin_group(settings, "CN=Fixture") is False
    assert not connection.search.called
    settings.ldap_admin_group_dn = "CN=Admins,DC=example"
    assert ldap._in_admin_group(settings, "CN=Fixture*(test)") is member
    assert connection.search.call_args.args[1] == r"(&(objectClass=groupOfNames)(member=CN=Fixture\2a\28test\29))"
    connection.unbind.assert_called_once()


@pytest.mark.parametrize("bind_ok", [True, False])
def test_password_verification_handles_transport_failure_and_closes_successful_binds(monkeypatch, settings, bind_ok):
    connection = MagicMock()
    constructor = MagicMock(return_value=connection, side_effect=None if bind_ok else ldap.LdapError("offline"))
    monkeypatch.setattr(ldap, "_build_connection", constructor)
    assert ldap._password_ok(settings, "CN=Fixture", "password") is bind_ok
    assert connection.unbind.call_count == int(bind_ok)
    ldap._safe_unbind(None)
    connection.unbind.side_effect = RuntimeError("closed")
    ldap._safe_unbind(connection)


@pytest.mark.parametrize("missing", ["enabled", "url", "base_dn", "username"])
def test_unconfigured_directory_or_blank_username_returns_without_network(monkeypatch, settings, missing):
    if missing == "enabled":
        settings.ldap_enabled = False
    elif missing == "url":
        settings.ldap_url = ""
    elif missing == "base_dn":
        settings.ldap_base_dn = ""
    search = MagicMock()
    monkeypatch.setattr(ldap, "get_settings", lambda: settings)
    monkeypatch.setattr(ldap, "_search_user", search)
    assert ldap.resolve_ldap_identity(" " if missing == "username" else "fixture", "password") is None
    search.assert_not_called()


@pytest.mark.parametrize("reason", ["user_not_found", "account_not_allowed", "bad_credentials"])
def test_directory_identity_failure_does_not_grant_admin_membership(monkeypatch, settings, reason):
    monkeypatch.setattr(ldap, "get_settings", lambda: settings)
    monkeypatch.setattr(
        ldap,
        "_search_user",
        lambda *args: None if reason == "user_not_found" else {"dn": "CN=Fixture,OU=Other", "display": "Fixture"},
    )
    if reason == "account_not_allowed":
        settings.ldap_required_ou = "Allowed"
    password = MagicMock(return_value=reason != "bad_credentials")
    admin = MagicMock()
    monkeypatch.setattr(ldap, "_password_ok", password)
    monkeypatch.setattr(ldap, "_in_admin_group", admin)
    with pytest.raises(ldap.LdapError, match=reason):
        ldap.resolve_ldap_identity("fixture", "password")
    admin.assert_not_called()
    if reason != "bad_credentials":
        password.assert_not_called()


@pytest.mark.parametrize(
    "default,admin,display,expected",
    [("operator", False, "Fixture", "operator"), (" ", False, "", "viewer"), (None, True, "", "admin")],
)
def test_verified_directory_identity_uses_configured_role_and_display_fallback(
    monkeypatch, settings, default, admin, display, expected
):
    settings.ldap_default_role = default
    monkeypatch.setattr(ldap, "get_settings", lambda: settings)
    monkeypatch.setattr(ldap, "_search_user", lambda *args: {"dn": "CN=Fixture", "display": display})
    monkeypatch.setattr(ldap, "_password_ok", lambda *args: True)
    monkeypatch.setattr(ldap, "_in_admin_group", lambda *args: admin)
    assert ldap.resolve_ldap_identity(" fixture ", None) == {
        "username": "fixture",
        "display_name": display or "fixture",
        "role": expected,
    }


@pytest.mark.parametrize("encoded", ["bad", "sha256$1$1$1$00$00", "scrypt$bad$1$1$00$00", "scrypt$1$1$1$xx$xx"])
def test_malformed_password_hashes_are_rejected(encoded):
    assert auth.verify_password("password", encoded) is False


def test_login_rate_limit_expires_per_identity_and_success_clears_it(monkeypatch):
    clock = {"now": 0}
    monkeypatch.setattr(auth, "time", SimpleNamespace(monotonic=lambda: clock["now"]))
    limiter = auth.LoginLimiter(attempts=2, window_seconds=5)
    limiter.fail("ip:user")
    limiter.fail("ip:user")
    limiter.check("ip:other")
    with pytest.raises(HTTPException) as failure:
        limiter.check("ip:user")
    assert failure.value.status_code == 429 and failure.value.detail["code"] == "LOGIN_RATE_LIMIT"
    clock["now"] = 6
    limiter.check("ip:user")
    limiter.fail("ip:user")
    limiter.clear("ip:user")
    limiter.check("ip:user")
    assert not limiter._entries["ip:user"]


def test_audit_storage_failure_does_not_break_authentication(monkeypatch):
    monkeypatch.setattr(auth.db, "connect", MagicMock(side_effect=RuntimeError("offline")))
    assert auth.audit_event(request=None, user=None, event_type="login", decision="deny") is None
