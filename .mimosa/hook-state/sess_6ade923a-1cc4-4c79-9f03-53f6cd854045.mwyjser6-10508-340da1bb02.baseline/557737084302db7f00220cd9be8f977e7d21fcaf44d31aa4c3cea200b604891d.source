"""Keep normalized finding references usable after an unambiguous passport reissue."""
from __future__ import annotations

from typing import Any

import psycopg


def rebind_reissued_findings(conn: psycopg.Connection[dict[str, Any]]) -> None:
    """Use the transaction's proven replacement map; preserve scan timestamps/raw evidence."""
    conn.execute(
        """UPDATE asset_card_vulnerabilities AS finding
           SET vulnerability_id = replacement.new_id
           FROM passport_id_replacements AS replacement
           WHERE finding.vulnerability_id = replacement.old_id"""
    )
