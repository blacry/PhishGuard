"""JSON-backed scan history and statistics."""

import json
from datetime import datetime, timezone
from pathlib import Path


HISTORY_FILE = Path(__file__).with_name("history.json")


def get_history():
    """Load all saved scans, returning an empty list when no history exists."""
    if not HISTORY_FILE.exists():
        return []

    with HISTORY_FILE.open("r", encoding="utf-8") as history_file:
        history = json.load(history_file)
    if not isinstance(history, list):
        raise ValueError("Scan history must contain a JSON list.")
    return history


def add_scan(scan_type, input_value, score, level):
    """Add one scan record to the local JSON history."""
    if scan_type not in ("URL", "Message"):
        raise ValueError("Scan type must be 'URL' or 'Message'.")
    if not isinstance(input_value, str):
        raise ValueError("Scan input must be text.")
    if not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError("Score must be an integer from 0 to 100.")
    if level not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        raise ValueError("Threat level is not recognized.")

    records = get_history()
    records.append({
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "type": scan_type,
        "input": input_value,
        "score": score,
        "level": level,
    })

    with HISTORY_FILE.open("w", encoding="utf-8") as history_file:
        json.dump(records, history_file, indent=2)


def clear_history():
    """Remove all saved scan records."""
    with HISTORY_FILE.open("w", encoding="utf-8") as history_file:
        json.dump([], history_file)


def get_stats():
    """Return totals, threat-level counts, and the average score."""
    records = get_history()
    counts = {
        level: sum(record.get("level") == level for record in records)
        for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    }
    total = len(records)
    average = (
        round(sum(record.get("score", 0) for record in records) / total, 1)
        if total
        else 0.0
    )
    return {
        "total_scans": total,
        "counts_per_level": counts,
        "average_score": average,
    }
