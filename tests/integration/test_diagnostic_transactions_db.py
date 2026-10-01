"""Real PostgreSQL transaction diagnostics: failure logs do not replace rollback semantics."""
import json

import psycopg
import pytest

from app import db, diagnostics

pytestmark = pytest.mark.integration


@pytest.fixture()
def transaction_logs(tmp_path, test_db):
    config = diagnostics.DiagnosticsConfig("DEBUG", tmp_path / "logs", 65536, 2, 14, False, 256, 24)
    diagnostics.configure_diagnostics(config, force=True)
    yield config
    diagnostics.shutdown_diagnostics()


def read_events(config):
    diagnostics.shutdown_diagnostics()
    return [json.loads(line) for line in (config.log_dir / "database.jsonl").read_text(encoding="utf-8").splitlines()]


def connect():
    return diagnostics.DiagnosticConnection.connect(db.DATABASE_URL, cursor_factory=diagnostics.DiagnosticCursor)


@pytest.mark.parametrize("generator", [False, True])
def test_batch_commit_preserves_data_and_omits_parameter_values(transaction_logs, generator):
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute("CREATE TEMP TABLE diagnostic_test(value TEXT)")
            values = [("fixture-private-parameter",), ("second",)]
            cursor.executemany("INSERT INTO diagnostic_test(value) VALUES(%s)", iter(values) if generator else values)
            connection.commit()
            cursor.execute("SELECT value FROM diagnostic_test ORDER BY value")
            assert cursor.fetchall() == [("fixture-private-parameter",), ("second",)]
    events = read_events(transaction_logs)
    assert {"db.query.completed", "db.batch.completed", "db.transaction.commit"} <= {item["event"] for item in events}
    assert "fixture-private-parameter" not in json.dumps(events)
    batch = next(item for item in events if item["event"] == "db.batch.started")
    assert batch.get("batch_size") == (None if generator else 2)


def test_invalid_sql_rolls_back_and_records_failure(transaction_logs):
    with pytest.raises(psycopg.errors.SyntaxError), connect() as connection:
        connection.execute("THIS IS INVALID SQL")
    events = read_events(transaction_logs)
    assert {"db.query.failed", "db.transaction.rollback"} <= {item["event"] for item in events}
    assert next(item for item in events if item["event"] == "db.query.failed")["exception"]["type"] == "SyntaxError"


def test_batch_failure_can_be_rolled_back_and_connection_reused(transaction_logs):
    with connect() as connection:
        connection.execute("CREATE TEMP TABLE diagnostic_test(value INTEGER UNIQUE)")
        connection.commit()
        with pytest.raises(psycopg.errors.UniqueViolation), connection.cursor() as cursor:
            cursor.executemany("INSERT INTO diagnostic_test(value) VALUES(%s)", [(1,), (1,)])
        connection.rollback()
        assert connection.execute("SELECT count(*) FROM diagnostic_test").fetchone() == (0,)
    events = read_events(transaction_logs)
    assert {"db.batch.failed", "db.transaction.rollback"} <= {item["event"] for item in events}


@pytest.mark.parametrize("explicit", [False, True])
def test_deferred_commit_failure_is_not_reported_as_success(transaction_logs, explicit):
    connection = connect()
    try:
        connection.execute("CREATE TEMP TABLE diagnostic_test(value INTEGER UNIQUE DEFERRABLE INITIALLY DEFERRED)")
        connection.commit()
        if explicit:
            connection.execute("INSERT INTO diagnostic_test VALUES(1),(1)")
            with pytest.raises(psycopg.errors.UniqueViolation):
                connection.commit()
            connection.rollback()
        else:
            with pytest.raises(psycopg.errors.UniqueViolation), connection:
                connection.execute("INSERT INTO diagnostic_test VALUES(1),(1)")
    finally:
        connection.close()
    events = read_events(transaction_logs)
    failed = [item for item in events if item["event"] in {"db.transaction.failed", "db.transaction.rollback"}]
    assert failed
    assert (failed[-1].get("intended_action") == "commit") if not explicit else any(item.get("reason") == "commit_failed" for item in failed)
