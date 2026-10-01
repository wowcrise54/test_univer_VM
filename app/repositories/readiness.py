from __future__ import annotations

from functools import cached_property
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

from .. import db


class ReadinessRepository:
    @cached_property
    def expected_heads(self) -> set[str]:
        root = Path(__file__).resolve().parents[2]
        config = Config(str(root / "alembic.ini"))
        config.set_main_option("script_location", str(root / "migrations"))
        return set(ScriptDirectory.from_config(config).get_heads())

    def probe(self) -> bool:
        with db.connect() as conn:
            exists = conn.execute(
                "SELECT to_regclass('public.alembic_version') IS NOT NULL AS present"
            ).fetchone()
            if not exists or not exists["present"]:
                return False
            rows = conn.execute("SELECT version_num FROM alembic_version").fetchall()
        return {row["version_num"] for row in rows} == self.expected_heads
