from __future__ import annotations

from types import TracebackType
from typing import Any, TypeAlias

import aiosqlite


RowDict: TypeAlias = dict[str, Any]


async def init_db(db_path: str) -> None:
    """Initialize the SQLite schema required by the SVP server."""
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")

        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                k_auth BLOB,
                totp_secret TEXT NULL
            )
            """
        )

        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vaults (
                id BLOB PRIMARY KEY,
                user_id INTEGER,
                version INTEGER,
                blob BLOB,
                ts INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )

        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token BLOB PRIMARY KEY,
                user_id INTEGER,
                expiry INTEGER,
                client_id BLOB,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )

        await conn.commit()


class DatabaseManager:
    """Async DAO wrapper around an aiosqlite connection."""

    def __init__(self, db_path: str) -> None:
        self._db_path: str = db_path
        self._conn: aiosqlite.Connection | None = None

    async def __aenter__(self) -> DatabaseManager:
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA foreign_keys = ON")
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        del exc_type, exc, tb
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    def _connection(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database connection is not initialized")
        return self._conn

    async def get_user_by_username(self, username: str) -> RowDict | None:
        conn: aiosqlite.Connection = self._connection()
        async with conn.execute(
            """
            SELECT id, username, k_auth, totp_secret
            FROM users
            WHERE username = ?
            """,
            (username,),
        ) as cursor:
            row: aiosqlite.Row | None = await cursor.fetchone()

        if row is None:
            return None
        return dict(row)

    async def create_user(self, username: str, k_auth: bytes) -> int:
        conn: aiosqlite.Connection = self._connection()
        async with conn.execute(
            """
            INSERT INTO users (username, k_auth, totp_secret)
            VALUES (?, ?, NULL)
            """,
            (username, k_auth),
        ) as cursor:
            await conn.commit()
            last_row_id: int | None = cursor.lastrowid

        if last_row_id is None:
            raise RuntimeError("Failed to create user")
        return int(last_row_id)

    async def create_session(
        self,
        token: bytes,
        user_id: int,
        expiry: int,
        client_id: bytes,
    ) -> None:
        conn: aiosqlite.Connection = self._connection()
        await conn.execute(
            """
            INSERT INTO sessions (token, user_id, expiry, client_id)
            VALUES (?, ?, ?, ?)
            """,
            (token, user_id, expiry, client_id),
        )
        await conn.commit()

    async def get_session(self, token: bytes) -> RowDict | None:
        conn: aiosqlite.Connection = self._connection()
        async with conn.execute(
            """
            SELECT token, user_id, expiry, client_id
            FROM sessions
            WHERE token = ?
            """,
            (token,),
        ) as cursor:
            row: aiosqlite.Row | None = await cursor.fetchone()

        if row is None:
            return None
        return dict(row)

    async def get_vault(self, vault_id: bytes) -> RowDict | None:
        conn: aiosqlite.Connection = self._connection()
        async with conn.execute(
            """
            SELECT id, user_id, version, blob, ts
            FROM vaults
            WHERE id = ?
            """,
            (vault_id,),
        ) as cursor:
            row: aiosqlite.Row | None = await cursor.fetchone()

        if row is None:
            return None
        return dict(row)

    async def update_vault(
        self,
        vault_id: bytes,
        user_id: int,
        version: int,
        blob: bytes,
        ts: int,
    ) -> bool:
        """Insert or CAS-update a vault row.

        Insert succeeds when the vault does not exist.
        Update succeeds only when the current version is exactly (version - 1),
        which provides optimistic locking semantics.
        """
        if version < 0:
            raise ValueError("version must be non-negative")

        conn: aiosqlite.Connection = self._connection()
        async with conn.execute(
            """
            INSERT INTO vaults (id, user_id, version, blob, ts)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                user_id = excluded.user_id,
                version = excluded.version,
                blob = excluded.blob,
                ts = excluded.ts
            WHERE vaults.user_id = excluded.user_id
              AND vaults.version = excluded.version - 1
            """,
            (vault_id, user_id, version, blob, ts),
        ) as cursor:
            await conn.commit()
            affected_rows: int = cursor.rowcount

        return affected_rows > 0
