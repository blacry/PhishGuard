# 🛡️ PhishGuard — Phishing Detection CLI Tool

> A Python command-line application that detects phishing indicators in URLs
> and text messages using explainable rules and an optional local feed check.

**Course:** Computational Thinking and Programming (2026CSAE100)  
**Version:** 1.0 (Rule-based, no ML)  
**License:** MIT

---

## 📋 What It Does

PhishGuard helps users identify phishing attempts by analyzing:
- **URLs** — checks for missing HTTPS, IP addresses, excessive subdomains,
  suspicious keywords, abnormal length, and special characters.
- **Text messages** — detects urgency language, threats, credential requests,
  and financial requests.

For each scan, it:
1. **Analyzes** the input against known phishing indicators
2. **Scores** the risk on a 0–100 scale (weighted sum, capped)
3. **Classifies** the threat as LOW / MEDIUM / HIGH / CRITICAL
4. **Explains** which indicators fired and why they're suspicious
5. **Recommends** what the user should do
6. **Saves** metadata to local SQLite history (input is redacted by default)
7. Optionally checks URLs against a locally cached phishing feed

⚠️ **Important:** PhishGuard never opens or visits submitted URLs. The
optional feed mode downloads threat data and compares it locally; it does not
send submitted URLs to the feed provider.

---

## 🚀 Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/PhishGuard.git
cd PhishGuard

# 2. (Recommended) Create a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# 3. Install runtime dependencies
pip install -r requirements.txt

# Install test tools when developing
pip install -r requirements-dev.txt
```

---

## 💻 Usage

```bash
python main.py
```

At a prompt, **Ctrl+C** cancels the current action without a traceback. At the
main menu, Ctrl+C or end-of-input exits cleanly. End-of-input is Ctrl+Z then
Enter in Windows terminals and Ctrl+D on macOS/Linux. An interrupted delete
confirmation never deletes scan history.

You'll see a menu:
```
=======================================================
       🛡️  PhishGuard — Phishing Detector v1.0
       Analyze URLs and messages for phishing risk
=======================================================

What would you like to do?
------------------------------
  1. Scan a URL
  2. Scan a message
  3. View scan history
  4. View statistics
  5. Delete scan history
  6. Exit
------------------------------
Enter your choice (1-6):
```

### Local history and privacy

Scan metadata is stored in `data/scan_history.sqlite3`. Submitted message/URL
content is **not stored by default**. To retain content encrypted, install the
requirements and configure a Fernet key in `PHISHGUARD_ENCRYPTION_KEY`:

```powershell
$env:PHISHGUARD_ENCRYPTION_KEY = python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Keep that key in a secure location; losing it means encrypted content cannot
be recovered. Set `PHISHGUARD_RETENTION_DAYS` to a positive integer to change
the default 90-day history retention. The menu's **Delete scan history** action
removes scan records but retains a content-free audit event.

History is written only to SQLite; CSV history import and export are not
supported. Existing SQLite databases are upgraded in place while retaining
their scan records. The old CSV was removed from the current tree, but earlier
Git commits or backups may still contain copies.

### Optional phishing reputation feed

The static checks do not send submitted URLs anywhere. To opt in to an
OpenPhish Community Feed download, set `PHISHGUARD_ENABLE_OPENPHISH=1` before
running PhishGuard:

```powershell
$env:PHISHGUARD_ENABLE_OPENPHISH = "1"
python main.py
```

PhishGuard downloads the public feed from
[OpenPhish](https://openphish.com/phishing_feeds.html) and compares exact
normalized URLs locally; it never submits the URL being scanned. OpenPhish
documents a 12-hour community-feed update cadence and its
[Terms of Use](https://openphish.com/terms.html); review those terms before
enabling it. Enabling feed updates makes outbound requests to OpenPhish/GitHub,
which can expose your network address, but the scanned URL is not included.
Feed refreshes are cached for 12 hours, rate-limited, and use a 10-second
timeout. If no fresh feed is available, the result is reported as
unknown/unavailable—not safe. An exact match in a fresh feed changes the
threat label to CRITICAL but does not change the separate heuristic score.
An entry found only in stale feed data is reported as unknown.

Run the local labeled-case benchmark (static heuristics only) with:

```powershell
python -m utils.benchmark
```

This uses the 10-case hand-authored regression dataset. The evaluator also
accepts a labeled CSV using the PhishGuard schema or a UCI PhiUSIIL file with
`URL` and `label` columns. It also recognizes the prepared Kaggle PhishGuard
CSV when its `description` values are `Kaggle source label: benign` or
`Kaggle source label: phishing`:

```powershell
python -m utils.benchmark --dataset data\evaluation_cases.csv
```

The UCI CSV is not bundled in the repository. Download and extract it from the
[UCI PhiUSIIL dataset page](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset),
then run:

```powershell
python -m utils.benchmark --dataset "C:\datasets\PhiUSIIL_Phishing_URL_Dataset.csv"
```

The PhishGuard CSV format has the header
`input_type,input,expected_threat_level,description`; input types are `url`
or `message`, and labels are `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. For
PhiUSIIL, label `0` means phishing and `1` means legitimate. The evaluator
uses only its URL and label columns, with any non-LOW result counted as an
alert. In the prepared Kaggle format, the explicit source-label description is
used to map phishing and benign rows to the binary classes. URLs are never
visited.

On the full UCI snapshot (235,795 URLs), the current rules had 60.4% binary
accuracy, 100% precision, 7.4% recall, 13.8% F1, zero false positives, and
93,491 false negatives. This is a result for that specific historical dataset,
not a claim about current real-world performance. The source was donated in 2024 and is licensed
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); dataset provenance
and label quality are not verified by the benchmark tool.

The evaluator also splits UCI URLs by hostname hash (80% development, 20%
holdout) and chooses a score cutoff by development-set F1. The current cutoff
of 25 had 13.3% holdout F1 and 0% false-positive rate. A development-selected
cutoff of 5 had 77.3% holdout F1, 64.3% recall, 97.0% precision, and a 1.5%
false-positive rate (396 false positives, 6,995 false negatives). This is
analysis only; the app's cutoff remains unchanged. The UCI dataset's phishing
prevalence is much higher than typical user traffic, so its precision does
not transfer directly to production.
For transparency, the benchmark also prints projected precision for the
development-selected cutoff at illustrative phishing prevalences of 0.1%,
1%, 5%, and 10%, using holdout recall and false-positive-rate point estimates.
At 1% assumed prevalence the projection is about 30%, not the measured 97%.
These scenarios are not real-traffic measurements or production forecasts.

### Kaggle Malicious URLs corpus

On the prepared 522,160-row Kaggle sample (428,074 benign and 94,086
phishing), the current cutoff of 25 produced 65.3% accuracy, 10.5% precision,
12.2% recall, 11.3% F1, and a 23.0% false-positive rate (98,370 false
positives; 82,597 false negatives). The data source is Kaggle's [Malicious
URLs dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset),
listed as CC0. The prepared sample contains only unique, unambiguous benign
and phishing URLs; six conflicting-label URLs were excluded, as were malware
and defacement rows. These results depend on the prepared labels and this
sample's high phishing share, and do not establish performance on live user
traffic.

A deterministic hostname-grouped 80/20 split contained 418,901 development
and 103,259 holdout URLs. The development F1-maximizing cutoff was 0
(30.6% F1, 100% FPR). On holdout it flagged every URL: 18.0% precision,
100% recall, 30.5% F1,
100% false-positive rate (84,701 false positives; 0 false negatives). At the
unchanged cutoff 25, holdout precision was 10.8%, recall 12.2%, F1 11.5%, and
false-positive rate 22.1% (18,739 false positives; 16,285 false negatives).
The all-alert candidate is not useful for selective detection and is reported
only as the result of the development-only F1 selection. Neither the candidate
nor any other cutoff was applied to the scanner.

## Container Deployment

Docker Compose builds a non-root CLI container. No network ports are exposed;
run it interactively and keep scan data in persistent Docker volumes:

```bash
docker compose build
docker compose run --rm phishguard
```

The SQLite database and reputation cache persist in the `phishguard-data`
volume; exported charts persist in `phishguard-visualizations`. OpenPhish
checks remain disabled by default. To opt in, set
`PHISHGUARD_ENABLE_OPENPHISH=1` in the environment before running Compose.
The encryption key can be passed through `PHISHGUARD_ENCRYPTION_KEY`; keep it
outside the image and Compose file.

The Docker build excludes local SQLite databases, feed caches, and other
runtime state so personal history is not copied into a distributable image.
Scan history is managed only through SQLite.

---

## 📁 Project Structure

```
PhishGuard/
├── main.py                          # CLI entry point (menu loop)
├── scanners/
│   ├── __init__.py
│   ├── url_scanner.py               # URL phishing checks (6 indicators)
│   ├── message_scanner.py           # Message language checks (4 indicators)
│   └── reputation.py                # Optional cached OpenPhish exact-URL checks
├── engine/
│   ├── __init__.py
│   ├── risk_engine.py               # Scoring + threat classification
│   └── recommendation_engine.py     # Explanations + safety tips
├── utils/
│   ├── __init__.py
│   ├── validators.py                # Input validation (is it a URL?)
│   ├── helpers.py                   # SQLite storage, retention, statistics
│   ├── charts.py                    # Matplotlib chart exports
│   ├── keywords.py                  # Keyword CSV validation and loading
│   └── benchmark.py                 # Local labeled-case evaluation
├── data/
│   ├── keywords.csv                 # Phishing keyword database
│   ├── test_cases.csv               # Pre-built test inputs
│   └── scan_history.sqlite3         # Local history database (created at runtime)
├── tests/
│   ├── test_scanner.py              # URL scanning, validation, and risk tests
│   ├── test_message_scanner.py      # Message scanner unit tests
│   ├── test_cli.py                  # CLI input and cancellation behavior
│   ├── test_visualization.py        # Chart export regression
│   ├── test_storage.py              # Storage privacy, retention, and statistics
│   ├── test_keywords.py             # Keyword-data validation tests
│   ├── test_reputation.py           # Offline reputation-feed tests
│   └── test_benchmark.py            # Benchmark regression tests
├── docs/                            # Full project documentation
├── reports/                         # Generated reports
├── visualizations/                  # Generated charts
├── screenshots/                     # App screenshots
├── requirements.txt                 # Python dependencies
├── requirements-dev.txt             # Test-only dependencies
├── Dockerfile                       # Non-root runtime image
├── compose.yaml                     # Interactive service and persistent volumes
├── .dockerignore                    # Excludes local state and development files
├── .github/workflows/ci.yml         # Test, benchmark, and image-build checks
├── .gitignore                       # Git ignore rules
├── LICENSE                          # MIT License
└── README.md                        # This file
```

---

## 🧪 Running Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -v
```

GitHub Actions runs the tests and benchmark on pushes, pull requests, or a
manual request, then builds the Docker image separately. It does not publish
an image to a registry.

The workflow instructions are stored in `.github/workflows/ci.yml`. YAML
(`.yml`) is a readable format for configuration, like a checklist of steps
for GitHub—not a programming language used by PhishGuard. You do not need to
learn or edit YAML to use the app.

---

## ⚠️ Limitations

- **Heuristic analysis** — cannot detect phishing pages that look
  identical to real sites (visual similarity). The optional feed is a
  separate signal, not a guarantee or a substitute for browsing protection.
- **Rule-based** — relies on heuristic weights, not machine learning.
  May produce false positives (safe things flagged) and false negatives
  (phishing things missed).
- **HTTPS misconception** — a site having HTTPS does NOT mean it's safe.
  Phishers use HTTPS too. Our HTTPS check has a low weight for this reason.
- **English only** — keyword detection works only for English text.
- **Feed coverage is limited** — the optional feed is cached and matches
  exact URLs only; absence from the feed is not evidence that a URL is safe.
- **Small benchmark** — its 10 hand-authored cases are for regression
  checks, not evidence of real-world accuracy.

See [docs/08_LIMITATIONS_AND_FUTURE.md](docs/08_LIMITATIONS_AND_FUTURE.md) for details.

---

## 📚 Documentation

Full documentation is in the `docs/` folder:

| File | Contents |
|------|----------|
| [01_PROJECT_OVERVIEW.md](docs/01_PROJECT_OVERVIEW.md) | Problem, objectives, scope |
| [02_ARCHITECTURE.md](docs/02_ARCHITECTURE.md) | Components, data flow |
| [03_ALGORITHM.md](docs/03_ALGORITHM.md) | Step-by-step algorithm + pseudocode |
| [04_INDICATORS_AND_WEIGHTS.md](docs/04_INDICATORS_AND_WEIGHTS.md) | Every indicator explained |
| [05_CODE_WALKTHROUGH.md](docs/05_CODE_WALKTHROUGH.md) | Module-by-module explanation |
| [06_TESTING.md](docs/06_TESTING.md) | Test strategy and test list |
| [07_VIVA_PREP.md](docs/07_VIVA_PREP.md) | Likely viva questions + answers |
| [08_LIMITATIONS_AND_FUTURE.md](docs/08_LIMITATIONS_AND_FUTURE.md) | Known limits, future work |
| [09_PROGRESS_LOG.md](docs/09_PROGRESS_LOG.md) | Dated development log |
| [10_GLOSSARY.md](docs/10_GLOSSARY.md) | All technical terms explained |

---

## 👤 Author

Built as a college project for BTech CSE, 2026.

---

*Stay safe online! 🛡️*
