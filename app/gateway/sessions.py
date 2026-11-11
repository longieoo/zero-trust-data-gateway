"""Persistent, bounded session allowlist. Store only hashes of token identifiers."""

import hashlib
from contextlib import contextmanager
import sqlite3
import time
from pathlib import Path

from psycopg_pool import ConnectionPool


class Sessions:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as database:
            database.execute(
                "CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, expires INTEGER NOT NULL)"
            )

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=3)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def identifier(claims):
        return hashlib.sha256(claims["jti"].encode()).hexdigest()

    def add(self, claims):
        with self.connect() as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute("DELETE FROM sessions WHERE expires <= ?", (int(time.time()),))
            if database.execute("SELECT count(*) FROM sessions").fetchone()[0] >= 10000:
                raise ValueError("Session capacity reached")
            database.execute(
                "INSERT INTO sessions VALUES (?, ?)", (self.identifier(claims), claims["exp"])
            )

    def active(self, claims):
        with self.connect() as database:
            row = database.execute(
                "SELECT expires FROM sessions WHERE id = ?", (self.identifier(claims),)
            ).fetchone()
            return bool(row and row[0] > time.time())

    def revoke(self, claims):
        with self.connect() as database:
            database.execute("DELETE FROM sessions WHERE id = ?", (self.identifier(claims),))


class PostgresSessions:
    """Shared allowlist with a separate role, no active-session cache.

    Revocation affects the next authentication on any instance; it does not cancel
    requests already in progress. Audit remains single-host SQLite independently.
    """

    def __init__(self, url):
        self.pool = ConnectionPool(
            url, min_size=0, max_size=5, timeout=3, kwargs={"connect_timeout": 3}, open=True
        )

    def close(self):
        self.pool.close()

    def add(self, claims):
        with self.pool.connection() as database:
            database.execute("SET LOCAL statement_timeout='3s'")
            database.execute("SELECT pg_advisory_xact_lock(587120)")
            database.execute(
                "DELETE FROM gateway_auth.sessions WHERE expires <= EXTRACT(EPOCH FROM now())"
            )
            if (
                database.execute("SELECT count(*) FROM gateway_auth.sessions").fetchone()[0]
                >= 10000
            ):
                raise ValueError("Session capacity reached")
            database.execute(
                "INSERT INTO gateway_auth.sessions(id,expires) VALUES (%s,%s)",
                (Sessions.identifier(claims), claims["exp"]),
            )

    def active(self, claims):
        with self.pool.connection() as database:
            database.execute("SET LOCAL statement_timeout='3s'")
            row = database.execute(
                "SELECT 1 FROM gateway_auth.sessions WHERE id=%s AND expires>EXTRACT(EPOCH FROM now())",
                (Sessions.identifier(claims),),
            ).fetchone()
            return row is not None

    def revoke(self, claims):
        with self.pool.connection() as database:
            database.execute("SET LOCAL statement_timeout='3s'")
            database.execute(
                "DELETE FROM gateway_auth.sessions WHERE id=%s", (Sessions.identifier(claims),)
            )
