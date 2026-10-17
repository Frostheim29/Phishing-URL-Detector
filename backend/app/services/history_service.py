from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parents[3]
DB_PATH = PROJECT_DIR / "phishguard.db"


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_database() -> None:
    connection = get_connection()

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                verdict TEXT NOT NULL,
                model_score REAL,
                heuristic_score INTEGER NOT NULL,
                analysis_mode TEXT NOT NULL,
                signals TEXT NOT NULL,
                positive_signals TEXT NOT NULL,
                negative_signals TEXT NOT NULL,
                strong_malicious_signals TEXT NOT NULL,
                analysis TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
            """
        )

        connection.commit()

    finally:
        connection.close()


def save_scan(result: dict[str, Any]) -> int:
    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            INSERT INTO scan_history (
                url,
                risk_score,
                risk_level,
                verdict,
                model_score,
                heuristic_score,
                analysis_mode,
                signals,
                positive_signals,
                negative_signals,
                strong_malicious_signals,
                analysis,
                scanned_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["url"],
                result["risk_score"],
                result["risk_level"],
                result["verdict"],
                result.get("model_score"),
                result["heuristic_score"],
                result["analysis_mode"],
                json.dumps(result.get("signals", [])),
                json.dumps(result.get("positive_signals", [])),
                json.dumps(result.get("negative_signals", [])),
                json.dumps(result.get("strong_malicious_signals", [])),
                json.dumps(result.get("analysis", {})),
                result["scanned_at"],
            ),
        )

        connection.commit()
        return int(cursor.lastrowid)

    finally:
        connection.close()


def get_history(limit: int = 50) -> list[dict[str, Any]]:
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                id,
                url,
                risk_score,
                risk_level,
                verdict,
                model_score,
                heuristic_score,
                analysis_mode,
                scanned_at
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def get_history_count() -> int:
    connection = get_connection()

    try:
        row = connection.execute(
            "SELECT COUNT(*) AS count FROM scan_history"
        ).fetchone()

        return int(row["count"])

    finally:
        connection.close()