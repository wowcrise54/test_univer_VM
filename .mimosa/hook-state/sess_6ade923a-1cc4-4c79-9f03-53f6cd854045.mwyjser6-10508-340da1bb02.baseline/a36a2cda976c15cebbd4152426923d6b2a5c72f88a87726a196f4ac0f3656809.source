from __future__ import annotations

import re
from collections.abc import Iterable
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network

MAX_TARGET_LENGTH = 253
_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


def normalize_scan_target(value: str) -> str:
    """Return the canonical MP VM scan target: an IP, a CIDR network, an IP range or an FQDN/hostname."""
    target = str(value or "").strip()
    if not target:
        raise ValueError("Пустая цель сканирования.")
    if len(target) > MAX_TARGET_LENGTH:
        raise ValueError(f"Цель «{target[:40]}…» длиннее {MAX_TARGET_LENGTH} символов.")
    try:
        if "/" in target:
            return str(ip_network(target, strict=False))
        if "-" in target:
            start_text, _, end_text = target.partition("-")
            bounds = [_ip_or_none(start_text), _ip_or_none(end_text)]
            if any(bounds):
                start, end = bounds
                if not start or not end or start.version != end.version or int(start) > int(end):
                    raise ValueError
                return f"{start}-{end}"
        elif ":" in target or target.replace(".", "").isdigit():
            return str(ip_address(target))
    except ValueError:
        raise ValueError(f"Некорректный IP-адрес, подсеть или диапазон: «{target}».") from None
    host = target.rstrip(".").lower()
    labels = host.split(".")
    # A numeric last label is a mistyped IP address, never a top-level domain.
    if not host or labels[-1].isdigit() or not all(_HOST_LABEL.match(label) for label in labels):
        raise ValueError(f"Некорректное FQDN-имя: «{target}».")
    return host


def _ip_or_none(value: str) -> IPv4Address | IPv6Address | None:
    try:
        return ip_address(value.strip())
    except ValueError:
        return None


def normalize_scan_targets(values: Iterable[str]) -> list[str]:
    """Normalize targets, keeping the first occurrence of each one."""
    return list(dict.fromkeys(normalize_scan_target(value) for value in values))
