"""SQLite-backed scan history with optional encryption for submitted input."""

import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)
MAX_STORED_INPUT_CHARACTERS = 4096
SCHEMA_VERSION = 3


def _get_database_path():
    """Return the SQLite database path."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, "..", "data", "scan_history.sqlite3")


def _get_retention_days():
    value = os.environ.get("PHISHGUARD_RETENTION_DAYS", "90")
    try:
        days = int(value)
    except ValueError as exc:
        raise ValueError("PHISHGUARD_RETENTION_DAYS must be a positive integer") from exc
    if days < 1:
        raise ValueError("PHISHGUARD_RETENTION_DAYS must be a positive integer")
    return days


def _get_fernet():
    key = os.environ.get("PHISHGUARD_ENCRYPTION_KEY")
    if not key:
        return None
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("PHISHGUARD_ENCRYPTION_KEY is not a valid Fernet key") from exc


def _record_audit_event(connection, action, details):
    connection.execute(
        "INSERT INTO audit_events (timestamp, action, details) VALUES (?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), action, details),
    )


def _prune_expired_scans(connection):
    cutoff = (datetime.now() - timedelta(days=_get_retention_days())).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    deleted = connection.execute(
        "DELETE FROM scans WHERE timestamp < ?", (cutoff,)
    ).rowcount
    connection.execute("DELETE FROM audit_events WHERE timestamp < ?", (cutoff,))
    if deleted:
        _record_audit_event(
            connection, "retention_pruned", f"Removed {deleted} expired scan record(s)."
        )


def _initialize_database(connection):
    schema_version = connection.execute("PRAGMA user_version").fetchone()[0]
    if schema_version > SCHEMA_VERSION:
        raise RuntimeError(
            f"Database schema version {schema_version} is newer than supported version {SCHEMA_VERSION}"
        )

    if schema_version == 0:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                input_type TEXT NOT NULL,
                input_ciphertext BLOB,
                risk_score INTEGER NOT NULL,
                threat_level TEXT NOT NULL,
                indicators TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL
            );
            """
        )
        connection.execute("PRAGMA user_version = 1")
        schema_version = 1

    if schema_version == 1:
        connection.execute(
            "ALTER TABLE scans ADD COLUMN reputation_status TEXT NOT NULL DEFAULT 'not_checked'"
        )
        connection.execute(
            "ALTER TABLE scans ADD COLUMN reputation_source TEXT NOT NULL DEFAULT 'none'"
        )
        connection.execute("PRAGMA user_version = 2")
        schema_version = 2

    if schema_version == 2:
        connection.execute("DROP TABLE IF EXISTS storage_metadata")
        connection.execute("PRAGMA user_version = 3")
        schema_version = 3

    if schema_version != SCHEMA_VERSION:
        raise RuntimeError(f"No migration path from database schema {schema_version}")


@contextmanager
def _connect_database():
    database_path = _get_database_path()
    os.makedirs(os.path.dirname(database_path), exist_ok=True)
    connection = sqlite3.connect(database_path, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        _initialize_database(connection)
        connection.commit()
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        logger.exception("SQLite history operation failed")
        raise
    finally:
        connection.close()


def _encrypt_input(raw_input):
    fernet = _get_fernet()
    if fernet is None or raw_input is None:
        return None
    bounded_input = str(raw_input)[:MAX_STORED_INPUT_CHARACTERS]
    return fernet.encrypt(bounded_input.encode("utf-8"))


def save_scan(scan_result):
    """Persist scan metadata and encrypt input only when a key is configured."""
    if not isinstance(scan_result, dict):
        return False

    try:
        encrypted_input = _encrypt_input(scan_result.get("input"))
        timestamp = scan_result.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with _connect_database() as connection:
            connection.execute(
                """INSERT INTO scans
                   (timestamp, input_type, input_ciphertext, risk_score, threat_level, indicators,
                    reputation_status, reputation_source)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(timestamp),
                    str(scan_result.get("input_type", "unknown")),
                    encrypted_input,
                    int(scan_result.get("risk_score", 0)),
                    str(scan_result.get("threat_level", "LOW")),
                    str(scan_result.get("indicators", "")),
                    str(scan_result.get("reputation_status", "not_checked")),
                    str(scan_result.get("reputation_source", "none")),
                ),
            )
            _prune_expired_scans(connection)
            _record_audit_event(connection, "scan_saved", "Stored one scan record.")
        return True
    except (OSError, sqlite3.Error, TypeError, ValueError, UnicodeError):
        logger.exception("Could not save scan history record")
        return False


def load_scan_history():
    """Load scan history; input content is redacted unless it can be decrypted."""
    try:
        fernet = _get_fernet()
        with _connect_database() as connection:
            _prune_expired_scans(connection)
            rows = connection.execute(
                """SELECT timestamp, input_type, input_ciphertext, risk_score, threat_level, indicators,
                          reputation_status, reputation_source
                   FROM scans ORDER BY id"""
            ).fetchall()
        records = []
        for row in rows:
            ciphertext = row["input_ciphertext"]
            if ciphertext is None:
                display_input = "[not stored]"
            elif fernet is None:
                display_input = "[encrypted; key unavailable]"
            else:
                try:
                    display_input = fernet.decrypt(ciphertext).decode("utf-8")
                except (InvalidToken, UnicodeError):
                    logger.warning("A stored scan input could not be decrypted")
                    display_input = "[encrypted; key unavailable]"
            records.append({
                "timestamp": row["timestamp"],
                "input_type": row["input_type"],
                "input": display_input,
                "risk_score": str(row["risk_score"]),
                "threat_level": row["threat_level"],
                "indicators": row["indicators"],
                "reputation_status": row["reputation_status"],
                "reputation_source": row["reputation_source"],
            })
        return records
    except (OSError, sqlite3.Error, ValueError):
        logger.exception("Could not load scan history")
        return []


def delete_scan_history():
    """Delete all scan records while retaining a content-free deletion audit event."""
    try:
        with _connect_database() as connection:
            deleted = connection.execute("DELETE FROM scans").rowcount
            _record_audit_event(connection, "history_deleted", f"Deleted {deleted} scan record(s).")
        return deleted
    except (OSError, sqlite3.Error):
        logger.exception("Could not delete scan history")
        return None


def generate_statistics():
    """
    Read scan history and compute summary statistics.

    Takes:   Nothing (reads from the local SQLite database).
    Returns: dict - {"total_scans": int,
                      "url_scans": int,
                      "message_scans": int,
                      "average_risk_score": float,
                      "threat_distribution": {"LOW": n, "MEDIUM": n,
                                              "HIGH": n, "CRITICAL": n}}
             Returns None if no history exists.
    """
    records = load_scan_history()
    if not records:
        return None

    total_scans = len(records)
    url_scans = 0
    message_scans = 0
    total_score = 0
    threat_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    for r in records:
        itype = r.get("input_type", "").lower()
        if itype == "url":
            url_scans += 1
        elif itype == "message":
            message_scans += 1

        try:
            score = int(r.get("risk_score", 0))
        except (ValueError, TypeError):
            score = 0
        total_score += score

        level = r.get("threat_level", "LOW").upper()
        if level in threat_dist:
            threat_dist[level] += 1
        else:
            threat_dist["LOW"] += 1

    avg_score = round(total_score / total_scans, 1) if total_scans > 0 else 0.0

    return {
        "total_scans": total_scans,
        "url_scans": url_scans,
        "message_scans": message_scans,
        "average_risk_score": avg_score,
        "threat_distribution": threat_dist
    }

