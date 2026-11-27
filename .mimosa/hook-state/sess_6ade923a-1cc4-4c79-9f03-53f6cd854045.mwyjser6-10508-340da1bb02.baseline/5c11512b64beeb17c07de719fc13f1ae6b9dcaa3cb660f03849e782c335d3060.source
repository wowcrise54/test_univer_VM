"""Legacy evidence is rederived on upgrade without discarding passports."""

import os
import subprocess

import psycopg
import pytest

from app import db
from tests.conftest import scratch_database

pytestmark = pytest.mark.integration


def test_risk_evidence_migration_rederives_legacy_rows_and_roundtrips(migrated_db):
    with scratch_database() as name:
        url = db.DATABASE_URL.rsplit("/", 1)[0] + "/" + name

        def migrate(*args):
            result = subprocess.run(["alembic", *args], env={**os.environ, "MPVM_DATABASE_URL": url}, capture_output=True, text=True, timeout=120)
            assert result.returncode == 0, result.stderr

        migrate("upgrade", "20260924_0024")
        with psycopg.connect(url) as conn:
            # Emulate the actual old schema: the fresh baseline now uses the
            # structured parser, but a deployed 0024 database used keywords.
            conn.execute("ALTER TABLE vulnerability_passports DROP COLUMN exploitation_evidence")
            conn.execute("ALTER TABLE vulnerability_passports ADD COLUMN exploitation_evidence BOOLEAN GENERATED ALWAYS AS (LOWER(COALESCE(raw_detail_json,'')) SIMILAR TO '%(exploit|exploited|эксплуат)%') STORED")
            conn.execute("INSERT INTO vulnerability_passports(internal_id,raw_detail_json,first_seen,last_seen) VALUES('legacy','{\"exploit\": false}','2026-10-01','2026-10-01')")
            assert conn.execute("SELECT exploitation_evidence FROM vulnerability_passports").fetchone()[0] is True
        migrate("upgrade", "head")
        with psycopg.connect(url) as conn:
            assert conn.execute("SELECT internal_id,exploitation_evidence,exploitation_evidence_source FROM vulnerability_passports").fetchone() == ("legacy", False, "raw_detail_json:exploit")
        migrate("downgrade", "20260924_0024")
        migrate("upgrade", "head")
        with psycopg.connect(url) as conn:
            assert conn.execute("SELECT exploitation_evidence,exploitation_evidence_source FROM vulnerability_passports").fetchone() == (False, "raw_detail_json:exploit")
