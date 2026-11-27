"""Privacy-conscious JSON scan history storage."""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

HISTORY_FILE = Path(__file__).with_name("scan_history.json")


def load_history(path=HISTORY_FILE):
    try:
        with open(path, "r", encoding="utf-8") as history_file:
            data = json.load(history_file)
        return data if isinstance(data, list) else []
    except FileNotFoundError:
        save_history([], path)
        return []
    except (json.JSONDecodeError, OSError):
        return []


def save_history(records, path=HISTORY_FILE):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as history_file:
        json.dump(records, history_file, indent=2, ensure_ascii=False)


def add_scan(category, summary, result, path=HISTORY_FILE):
    records = load_history(path)
    scan = {
        "id": str(uuid.uuid4()), "timestamp": datetime.now(timezone.utc).isoformat(),
        "category": category, "summary": (summary or "")[:160],
        "score": result["score"], "classification": result["classification"],
        "findings": [{key: item.get(key) for key in ("key", "indicator", "points", "severity", "explanation")} for item in result.get("findings", [])],
    }
    records.insert(0, scan)
    save_history(records, path)
    return scan


def delete_scan(scan_id, path=HISTORY_FILE):
    records = [record for record in load_history(path) if record.get("id") != scan_id]
    save_history(records, path)
    return records


def clear_history(path=HISTORY_FILE):
    save_history([], path)
