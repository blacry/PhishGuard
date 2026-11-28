# Code module guide

| Path | Responsibility |
| --- | --- |
| `app.py` | Page layout, URL form, cached database loading, and verdict display |
| `database/urlhaus_database.py` | URL normalization, archive parsing, exact matching, and host matching |
| `data/full.csv.zip` | Supplied URLhaus data snapshot |
| `tests/test_urlhaus_database.py` | Tests using a small synthetic ZIP fixture |
| `requirements.txt` | Streamlit dependency |

## Important functions

- `normalize_url(value)` returns a canonical key or `None` for invalid input.
- `load_database(path)` parses the CSV in the archive and builds URL and hostname dictionaries.
- `check_url(value, database)` returns `malware`, `related_host`, `not_listed`, `invalid`, or `database_error`.
- `get_database()` in `app.py` caches the loaded indexes for the lifetime of the Streamlit process.

## Explanation for the viva

“I used a dictionary for exact URL lookup because dictionary membership is fast. I also built a second dictionary keyed by hostname so the app can warn when a different malicious URL exists on that same host. The parser reads the CSV directly from the ZIP, so the user does not have to extract the large text file.”
