"""Connection transaction semantics for pooled checkouts."""

from __future__ import annotations

from typing import Any

from psycopg_pool import ConnectionPool

from app.diagnostics import DiagnosticConnection


class PooledConnection(DiagnosticConnection):
    """Pool member with ``with connect() as conn`` semantics.

    Leaving the ``with`` block commits (or rolls back on error) and returns the
    connection to the pool instead of closing it. Outside a checkout it behaves
    like any other connection, so the pool can still close it normally.
    """

    _mpvm_checkout_pool: ConnectionPool | None = None

    def __exit__(self, exc_type: Any, exc_value: Any, traceback_value: Any) -> None:
        pool = self._mpvm_checkout_pool
        if pool is None:
            return super().__exit__(exc_type, exc_value, traceback_value)
        self._mpvm_checkout_pool = None
        try:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        finally:
            # putconn() discards a connection that is broken or still in a transaction.
            pool.putconn(self)
        return None
