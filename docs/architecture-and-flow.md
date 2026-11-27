# Architecture and lookup flow

## Components

- `app.py` — Streamlit page, input form, and result presentation.
- `database/urlhaus_database.py` — URL normalization, CSV parsing, and matching.
- `data/full.csv.zip` — supplied URLhaus dump, read directly without extraction.
- `tests/test_urlhaus_database.py` — unit tests for matching behavior.

## Lookup flow

```text
User enters URL
      ↓
Streamlit form submits text
      ↓
normalize_url() removes scheme/fragment differences
      ↓
check_url() checks exact URL index
      ├── exact match → MALWARE
      ├── hostname match only → POTENTIALLY MALICIOUS
      └── no match → NOT LISTED
```

At app startup, `load_database()` streams the CSV member from the ZIP file and builds two dictionaries:

- `by_url`: canonical URL key to database record.
- `by_host`: hostname to its database records.

Streamlit's `cache_resource` keeps those indexes in memory across page reruns, so the ZIP is parsed once per app process.

## Why a local snapshot?

The app can run without an API key or internet access. The result is repeatable for the same database snapshot. The tradeoff is that the local data does not update automatically.
