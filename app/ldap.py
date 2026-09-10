"""LDAP (corporate directory) login support.

Local login is always tried first; when it fails and LDAP is configured,
the credentials are verified against the directory. The directory identity
maps onto a regular local ``app_users`` row: the first successful LDAP
login provisions the local user automatically.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from app.core import get_settings

logger = logging.getLogger("mpvm.ldap")


class LdapError(Exception):
    """Raised when LDAP authentication fails or cannot be completed."""


def _escape_filter_value(value: str) -> str:
    """Escape a value before interpolating it into an LDAP filter (RFC 4515)."""
    from ldap3.utils.conv import escape_filter_chars
    return escape_filter_chars(value)


def _filter_for(username: str, settings) -> str:
    return settings.ldap_user_filter.replace("{username}", _escape_filter_value(username))


def _build_connection(settings, user: str | None = None, password: str | None = None):
    import ldap3

    try:
        parsed = urlparse((settings.ldap_url or "").strip())
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise LdapError("invalid_ldap_url") from exc

    if parsed.scheme not in {"ldap", "ldaps"} or not hostname:
        raise LdapError("invalid_ldap_url")

    # ldap3 does not reliably infer SSL from a URL when use_ssl is supplied
    # explicitly.  Derive both the transport and the default port here so
    # ldaps://...:636 works as documented in .env.example.
    use_ssl = parsed.scheme == "ldaps"
    port = port or (636 if use_ssl else 389)

    server = ldap3.Server(
        parsed.hostname,
        port=port,
        get_info=ldap3.NONE,
        use_ssl=use_ssl,
        connect_timeout=max(1, settings.ldap_connect_timeout_seconds),
    )
    try:
        return ldap3.Connection(
            server,
            user=user or None,
            password=password if password is not None else None,
            auto_bind=True,
            read_only=True,
        )
    except Exception as exc:  # noqa: BLE001 - normalize ldap3 failures for auth
        # Never let LDAPBindError escape through FastAPI as a 500.  The login
        # layer deliberately converts LdapError into the normal 401 response.
        description = getattr(exc, "message", None) or str(exc) or exc.__class__.__name__
        if not user:
            bind_kind = "anonymous account"
        elif user == getattr(settings, "ldap_bind_dn", ""):
            bind_kind = "lookup account"
        else:
            bind_kind = "user account"
        logger.warning(
            "LDAP bind failed for %s: %s",
            bind_kind,
            description,
        )
        raise LdapError("ldap_bind_failed") from exc


def _search_user(settings, username: str) -> dict | None:
    """Locate the user entry; returns {dn, display} or None when not found."""
    connection = _build_connection(settings, settings.ldap_bind_dn or None, settings.ldap_bind_password or None)
    try:
        if not connection.search(
            settings.ldap_base_dn,
            _filter_for(username, settings),
            size_limit=2,
            attributes=[settings.ldap_display_name_attribute, "displayName", "cn"],
        ):
            raise LdapError(f"LDAP-поиск завершился с ошибкой: {connection.result.get('description', 'unknown')}")
    finally:
        _safe_unbind(connection)
    if not connection.entries:
        return None
    if len(connection.entries) > 1:
        logger.warning("LDAP-фильтр %r вернул %d записей, используется первая", settings.ldap_user_filter, len(connection.entries))
    entry = connection.entries[0]
    display = ""
    for attr in (settings.ldap_display_name_attribute, "displayName", "cn"):
        if attr in entry:
            display = str(entry[attr])
            break
    return {"dn": str(entry.entry_dn), "display": display}


def _password_ok(settings, user_dn: str, password: str) -> bool:
    """Verify the password by re-binding as the located user DN."""
    check = None
    try:
        check = _build_connection(settings, user_dn, password)
        return True
    except Exception:  # noqa: BLE001 - any bind/network failure = bad credentials
        return False
    finally:
        _safe_unbind(check)


def _in_admin_group(settings, user_dn: str) -> bool:
    if not settings.ldap_admin_group_dn:
        return False
    safe_dn = _escape_filter_value(user_dn)
    connection = _build_connection(settings, settings.ldap_bind_dn or None, settings.ldap_bind_password or None)
    try:
        if not connection.search(
            settings.ldap_admin_group_dn,
            f"(&(objectClass=groupOfNames)(member={safe_dn}))",
            size_limit=1,
            attributes=["dn"],
        ):
            raise LdapError(f"LDAP-проверка группы завершилась с ошибкой: {connection.result.get('description', 'unknown')}")
        return bool(connection.entries)
    finally:
        _safe_unbind(connection)


def _safe_unbind(connection) -> None:
    if connection is None:
        return
    try:
        connection.unbind()
    except Exception:  # noqa: BLE001 - unbind failures are not fatal
        pass


def resolve_ldap_identity(username: str, password: str) -> dict | None:
    """Verify credentials against LDAP and return the mapped identity.

    Returns ``None`` when LDAP is disabled or not fully configured.
    Raises :class:`LdapError` when the user is unknown or the password
    does not match.
    """
    settings = get_settings()
    if not settings.ldap_enabled or not settings.ldap_url or not settings.ldap_base_dn:
        return None
    username = (username or "").strip()
    if not username:
        return None

    found = _search_user(settings, username)
    if not found:
        logger.info("LDAP: пользователь %s не найден", username)
        raise LdapError("user_not_found")
    if not _password_ok(settings, found["dn"], password or ""):
        logger.info("LDAP: неверный пароль для %s", username)
        raise LdapError("bad_credentials")

    role = (settings.ldap_default_role or "viewer").strip() or "viewer"
    if _in_admin_group(settings, found["dn"]):
        role = "admin"
    return {
        "username": username,
        "display_name": found["display"] or username,
        "role": role,
    }
