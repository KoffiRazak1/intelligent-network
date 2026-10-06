"""Stockage SQLite de l'historique et des résumés de paquets."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


DEFAULT_DATABASE_PATH = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "network_analyzer.db"
)


class HistoryStore:
    """Enregistre les sessions et les résumés des paquets observés."""

    def __init__(
        self,
        database_path: str | Path | None = None,
    ) -> None:
        configured_path = database_path or os.getenv("DATABASE_PATH")
        self.database_path = Path(configured_path or DEFAULT_DATABASE_PATH)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        """Ouvre une connexion indépendante à la base."""
        connection = sqlite3.connect(self.database_path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_database(self) -> None:
        """Crée les tables nécessaires si elles n'existent pas."""
        connection = self._connect()

        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS capture_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    interface_id TEXT NOT NULL,
                    interface_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    packet_count INTEGER NOT NULL DEFAULT 0,
                    bytes_captured INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT NOT NULL,
                    ended_at TEXT
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS packet_summaries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    packet_index INTEGER NOT NULL,
                    packet_json TEXT NOT NULL,
                    FOREIGN KEY (session_id)
                        REFERENCES capture_sessions (id)
                        ON DELETE CASCADE,
                    UNIQUE (session_id, packet_index)
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_packet_summaries_session
                ON packet_summaries (session_id, packet_index)
                """
            )

            connection.commit()
        finally:
            connection.close()

    def recover_interrupted_sessions(self) -> int:
        """Marque comme interrompues les sessions encore actives au démarrage."""
        connection = self._connect()

        try:
            cursor = connection.execute(
                """
                UPDATE capture_sessions
                SET
                    status = 'INTERRUPTED',
                    ended_at = ?
                WHERE status = 'RUNNING'
                """,
                (datetime.now(timezone.utc).isoformat(),),
            )
            connection.commit()
            return cursor.rowcount
        finally:
            connection.close()

    def create_session(
        self,
        interface_id: str,
        interface_name: str,
        started_at: str,
    ) -> int:
        """Crée une session et renvoie son identifiant."""
        connection = self._connect()

        try:
            cursor = connection.execute(
                """
                INSERT INTO capture_sessions (
                    interface_id,
                    interface_name,
                    status,
                    packet_count,
                    bytes_captured,
                    started_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    interface_id,
                    interface_name,
                    "RUNNING",
                    0,
                    0,
                    started_at,
                ),
            )
            connection.commit()

            if cursor.lastrowid is None:
                raise RuntimeError(
                    "La session a été créée sans recevoir d'identifiant."
                )

            return int(cursor.lastrowid)
        finally:
            connection.close()

    def finish_session(
        self,
        session_id: int,
        status: str,
        ended_at: str,
        packet_count: int,
        bytes_captured: int,
    ) -> None:
        """Met à jour l'état final et les compteurs d'une session."""
        connection = self._connect()

        try:
            cursor = connection.execute(
                """
                UPDATE capture_sessions
                SET
                    status = ?,
                    ended_at = ?,
                    packet_count = ?,
                    bytes_captured = ?
                WHERE id = ?
                """,
                (
                    status,
                    ended_at,
                    max(0, int(packet_count)),
                    max(0, int(bytes_captured)),
                    session_id,
                ),
            )
            connection.commit()

            if cursor.rowcount == 0:
                raise KeyError(f"Session inconnue : {session_id}")
        finally:
            connection.close()

    def save_packet_summaries(
        self,
        session_id: int,
        packets: list[tuple[int, dict[str, Any]]],
    ) -> None:
        """Enregistre un lot de résumés de paquets pour une session."""
        if not packets:
            return

        connection = self._connect()

        try:
            connection.executemany(
                """
                INSERT OR IGNORE INTO packet_summaries (
                    session_id,
                    packet_index,
                    packet_json
                )
                VALUES (?, ?, ?)
                """,
                [
                    (
                        session_id,
                        packet_index,
                        json.dumps(
                            packet,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        ),
                    )
                    for packet_index, packet in packets
                ],
            )
            connection.commit()
        finally:
            connection.close()

    def has_session(self, session_id: int) -> bool:
        """Indique si une session existe."""
        connection = self._connect()

        try:
            row = connection.execute(
                "SELECT 1 FROM capture_sessions WHERE id = ?",
                (session_id,),
            ).fetchone()
            return row is not None
        finally:
            connection.close()

    def iter_packet_summaries(
        self,
        session_id: int,
        batch_size: int = 500,
    ) -> Iterator[dict[str, Any]]:
        """Lit les résumés d'une session par lots, dans l'ordre de capture."""
        safe_batch_size = max(1, min(int(batch_size), 5000))
        connection = self._connect()

        try:
            cursor = connection.execute(
                """
                SELECT packet_json
                FROM packet_summaries
                WHERE session_id = ?
                ORDER BY packet_index ASC
                """,
                (session_id,),
            )

            while True:
                rows = cursor.fetchmany(safe_batch_size)
                if not rows:
                    break

                for row in rows:
                    yield json.loads(row["packet_json"])
        finally:
            connection.close()

    def list_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        """Renvoie les sessions les plus récentes en premier."""
        safe_limit = max(1, min(int(limit), 500))
        connection = self._connect()

        try:
            rows = connection.execute(
                """
                SELECT
                    id,
                    interface_id,
                    interface_name,
                    status,
                    packet_count,
                    bytes_captured,
                    started_at,
                    ended_at
                FROM capture_sessions
                ORDER BY id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()

            return [dict(row) for row in rows]
        finally:
            connection.close()
