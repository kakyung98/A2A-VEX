from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import sqlite3
from typing import Iterator

from cve_genie_web.config import settings


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(
        settings.database_path,
        check_same_thread=False,
    )
    connection.row_factory = sqlite3.Row
    return connection


def _column_names(connection: sqlite3.Connection) -> set[str]:
    rows = connection.execute("PRAGMA table_info(jobs)").fetchall()
    return {str(row["name"]) for row in rows}


def _add_column_if_missing(
    connection: sqlite3.Connection,
    *,
    column_name: str,
    definition: str,
) -> None:
    if column_name not in _column_names(connection):
        connection.execute(
            f"ALTER TABLE jobs ADD COLUMN {column_name} {definition}"
        )


def initialize_database() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                cve_id TEXT NOT NULL,
                status TEXT NOT NULL,
                stage TEXT NOT NULL,
                message TEXT,
                input_json_path TEXT,
                log_path TEXT,
                result_path TEXT,
                exit_code INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                run_type TEXT NOT NULL DEFAULT 'build,exploit,verify',
                missing_fields_json TEXT NOT NULL DEFAULT '[]',
                reproduction_status TEXT NOT NULL DEFAULT 'unknown',
                exploitable INTEGER,
                verifier_passed INTEGER,
                final_reason TEXT
            )
            """
        )

        migrations = {
            "run_type": "TEXT NOT NULL DEFAULT 'build,exploit,verify'",
            "missing_fields_json": "TEXT NOT NULL DEFAULT '[]'",
            "reproduction_status": "TEXT NOT NULL DEFAULT 'unknown'",
            "exploitable": "INTEGER",
            "verifier_passed": "INTEGER",
            "final_reason": "TEXT",
        }

        for column_name, definition in migrations.items():
            _add_column_if_missing(
                connection,
                column_name=column_name,
                definition=definition,
            )

        connection.commit()


@contextmanager
def db_session() -> Iterator[sqlite3.Connection]:
    connection = connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
