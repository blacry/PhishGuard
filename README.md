# PhishGuard URL Check

PhishGuard checks a submitted URL against the local URLhaus malware URL database supplied in `data/full.csv.zip`.

## What it reports

- **MALWARE** — the normalized full URL exactly matches a URLhaus record.
- **POTENTIALLY MALICIOUS** — the submitted URL is not an exact match, but its hostname has one or more URLhaus records.
- **NOT LISTED** — neither the exact URL nor hostname appears in this local database snapshot.

“Not listed” means the URL might be safe, but it could also be new or missing from the local snapshot. This tool only searches the included database. It does not visit the URL or contact any online service.

## Run it

Python 3.10 or newer is recommended.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

Open the local address printed by Streamlit, usually `http://localhost:8501`.

## Database

The supplied archive contains the URLhaus CSV dump. The app reads it directly from the ZIP, so it does not need to extract a second copy. The current snapshot contains 176,240 unique URL records and includes its own last-updated timestamp. See [data/README.md](data/README.md) for attribution and format details.

## Test

```powershell
python -m unittest discover -s tests -v
```

See the [viva documentation](docs/README.md) for the architecture, database behavior, limitations, and demo questions.
