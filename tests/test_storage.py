import sqlite3

from cryptography.fernet import Fernet

from utils import helpers


def _scan(input_text="private message"):
    return {
        "input_type": "message",
        "input": input_text,
        "risk_score": 40,
        "threat_level": "MEDIUM",
        "indicators": "credential_request",
    }


def test_input_is_not_stored_without_encryption_key(monkeypatch):
    monkeypatch.delenv("PHISHGUARD_ENCRYPTION_KEY", raising=False)

    assert helpers.save_scan(_scan()) is True
    record = helpers.load_scan_history()[0]

    assert record["input"] == "[not stored]"
    with helpers._connect_database() as connection:
        ciphertext = connection.execute(
            "SELECT input_ciphertext FROM scans"
        ).fetchone()[0]
    assert ciphertext is None


def test_input_is_encrypted_and_decryptable_with_configured_key(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setenv("PHISHGUARD_ENCRYPTION_KEY", key.decode("ascii"))

    assert helpers.save_scan(_scan()) is True
    assert helpers.load_scan_history()[0]["input"] == "private message"

    with helpers._connect_database() as connection:
        ciphertext = connection.execute(
            "SELECT input_ciphertext FROM scans"
        ).fetchone()[0]
    assert b"private message" not in ciphertext
    monkeypatch.delenv("PHISHGUARD_ENCRYPTION_KEY")
    assert helpers.load_scan_history()[0]["input"] == "[encrypted; key unavailable]"


def test_encrypted_input_is_limited_to_maximum_length(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setenv("PHISHGUARD_ENCRYPTION_KEY", key.decode("ascii"))
    submitted = "x" * (helpers.MAX_STORED_INPUT_CHARACTERS + 20)

    assert helpers.save_scan(_scan(submitted)) is True
    assert len(helpers.load_scan_history()[0]["input"]) == helpers.MAX_STORED_INPUT_CHARACTERS


def test_retention_and_history_deletion_are_audited(monkeypatch):
    monkeypatch.delenv("PHISHGUARD_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("PHISHGUARD_RETENTION_DAYS", "30")

    old_scan = _scan("old")
    old_scan["timestamp"] = "2020-01-01 00:00:00"
    assert helpers.save_scan(old_scan) is True
    assert helpers.save_scan(_scan("current")) is True
    assert [row["input"] for row in helpers.load_scan_history()] == ["[not stored]"]

    assert helpers.delete_scan_history() == 1
    assert helpers.load_scan_history() == []
    with helpers._connect_database() as connection:
        actions = [
            row[0] for row in connection.execute(
                "SELECT action FROM audit_events ORDER BY id"
            ).fetchall()
        ]
    assert "retention_pruned" in actions
    assert "history_deleted" in actions


def test_invalid_encryption_key_does_not_store_input(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_ENCRYPTION_KEY", "not-a-fernet-key")

    assert helpers.save_scan(_scan()) is False
    assert helpers.load_scan_history() == []


def test_schema_v1_migrates_and_removes_unused_metadata():
    database_path = helpers._get_database_path()
    connection = sqlite3.connect(database_path)
    connection.executescript(
        """
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            input_type TEXT NOT NULL,
            input_ciphertext BLOB,
            risk_score INTEGER NOT NULL,
            threat_level TEXT NOT NULL,
            indicators TEXT NOT NULL
        );
        CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL
        );
        CREATE TABLE storage_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO scans
            (timestamp, input_type, risk_score, threat_level, indicators)
            VALUES ('2026-01-01 00:00:00', 'url', 20, 'LOW', 'https_check');
        PRAGMA user_version = 1;
        """
    )
    connection.close()

    with helpers._connect_database() as migrated:
        version = migrated.execute("PRAGMA user_version").fetchone()[0]
        columns = {
            row["name"] for row in migrated.execute("PRAGMA table_info(scans)").fetchall()
        }
        scan_count = migrated.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        tables = {
            row["name"]
            for row in migrated.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }

    assert version == helpers.SCHEMA_VERSION
    assert {"reputation_status", "reputation_source"} <= columns
    assert scan_count == 1
    assert "storage_metadata" not in tables
