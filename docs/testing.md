# Tests

Run the suite from the project root:

```powershell
python -m unittest discover -s tests -v
```

Tests use small synthetic URLhaus ZIP files, so they do not depend on the full database or network access.

Coverage includes:

- URL normalization (scheme and fragment handling).
- Invalid URL rejection.
- Exact URL matches.
- Host-only related matches.
- URLs absent from the database.
- Missing or malformed database files.
- Parsing comment headers and CSV records from a ZIP archive.

For a manual check against the supplied database, enter a URL copied from one of its records. The matching result should say `MALWARE`. Use only the text value; never open the URL.
