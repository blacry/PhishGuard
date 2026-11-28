"""Read and search a local URLhaus CSV dump stored inside a ZIP archive."""

import csv
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

DATABASE_FILE = Path(__file__).resolve().parents[1] / "data" / "full.csv.zip"


def normalize_url(value):
    """Build a comparable URL key without scheme or fragment differences."""
    value = (value or "").strip()
    if not value:
        return None
    if "://" not in value:
        value = "https://" + value

    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        if any(character.isspace() for character in parsed.hostname):
            return None
        hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        port = parsed.port
    except (UnicodeError, ValueError):
        return None

    if port and port not in {80, 443}:
        hostname += ":" + str(port)
    path = parsed.path or "/"
    key = hostname + path
    if parsed.query:
        key += "?" + parsed.query
    return key


def _parse_header(row):
    return [cell.strip().lstrip("# ").strip() for cell in row]


def load_database(path=DATABASE_FILE):
    """Load URL records and simple host indexes from the supplied ZIP dump."""
    path = Path(path)
    if not path.exists():
        return {"ok": False, "error": f"Database file was not found: {path}", "by_url": {}, "by_host": {}, "count": 0, "updated": "Unknown"}

    by_url = {}
    by_host = {}
    header = None
    updated = "Unknown"

    try:
        with zipfile.ZipFile(path, "r") as archive:
            members = [item for item in archive.infolist() if item.filename.lower().endswith((".csv", ".txt"))]
            if not members:
                return {"ok": False, "error": "The ZIP archive does not contain a CSV or TXT data file.", "by_url": {}, "by_host": {}, "count": 0, "updated": updated}
            if members[0].file_size > 250_000_000:
                return {"ok": False, "error": "The uncompressed database is larger than the 250 MB safety limit.", "by_url": {}, "by_host": {}, "count": 0, "updated": updated}

            with archive.open(members[0], "r") as source:
                import io

                text_file = io.TextIOWrapper(source, encoding="utf-8-sig", errors="replace", newline="")
                reader = csv.reader(text_file)
                for row in reader:
                    if not row:
                        continue
                    first_cell = row[0].strip()
                    if first_cell.startswith("# Last updated:"):
                        updated = first_cell.removeprefix("# Last updated:").strip()
                        continue
                    if first_cell.startswith("# id"):
                        header = _parse_header(row)
                        continue
                    if first_cell.startswith("#") or header is None or len(row) < len(header):
                        continue

                    record = dict(zip(header, (cell.strip() for cell in row)))
                    raw_url = record.get("url", "")
                    key = normalize_url(raw_url)
                    if not key:
                        continue
                    hostname = urlsplit("https://" + raw_url.split("://", 1)[-1]).hostname
                    if not hostname:
                        continue
                    hostname = hostname.encode("idna").decode("ascii").lower().rstrip(".")
                    by_url[key] = record
                    by_host.setdefault(hostname, []).append(record)
    except (OSError, zipfile.BadZipFile, csv.Error, UnicodeError) as error:
        return {"ok": False, "error": "Could not read the URLhaus database: " + str(error), "by_url": {}, "by_host": {}, "count": 0, "updated": updated}

    if not header:
        return {"ok": False, "error": "The database header was not found in the archive.", "by_url": {}, "by_host": {}, "count": 0, "updated": updated}
    return {"ok": True, "error": None, "by_url": by_url, "by_host": by_host, "count": len(by_url), "updated": updated}


def check_url(value, database):
    """Return exact URL, related-host, or no-match status from local data."""
    key = normalize_url(value)
    if not key:
        return {"status": "invalid", "record": None, "related": [], "error": "Enter a valid HTTP or HTTPS URL."}
    if not database.get("ok"):
        return {"status": "database_error", "record": None, "related": [], "error": database.get("error", "Database unavailable.")}

    record = database["by_url"].get(key)
    if record:
        return {"status": "malware", "record": record, "related": [], "error": None}

    parsed = urlsplit("https://" + key)
    related = database["by_host"].get(parsed.hostname or "", [])
    if related:
        return {"status": "related_host", "record": None, "related": related[:5], "error": None}
    return {"status": "not_listed", "record": None, "related": [], "error": None}
