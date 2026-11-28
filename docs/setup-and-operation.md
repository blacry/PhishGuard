# Setup and operation

## Requirements

- Python 3.10 or newer
- `data/full.csv.zip` in the project folder

The app performs its check offline; internet is not needed after installation.

## Install and run on Windows

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

Open the local URL printed by Streamlit, usually `http://localhost:8501`.

## How to use

1. Paste a URL into **URL to check**.
2. Select **Check URL**.
3. Read whether it is an exact malware match, a related-host warning, or not listed.
4. Do not interpret “not listed” as “safe.”

## Refresh the dataset

Replace `data/full.csv.zip` with a newer URLhaus CSV dump in the same format. Stop and restart Streamlit to reload its cached in-memory index. The app does not update the file automatically.

## Troubleshooting

- **Database missing:** put the supplied archive at `data/full.csv.zip`.
- **Archive format error:** confirm the ZIP contains a `.csv` or `.txt` CSV dump and has not been renamed from another format.
- **URL invalid:** enter an HTTP/HTTPS URL or a hostname with an optional path.
- **Unexpected not-listed result:** compare the exact path and query with the database; the app preserves both when matching.
