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

This uses the 10-case hand-authored regression dataset. To evaluate another
labeled CSV, use:

```powershell
python -m utils.benchmark --dataset data\evaluation_cases.csv
```

The CSV must have the header
`input_type,input,expected_threat_level,description`; input type must be
`url` or `message`, and labels must be `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
The report includes exact-label accuracy, alert precision/recall/F1,
false-positive and false-negative counts, a confusion matrix, and metrics
separately for URLs and messages. The evaluator uses static rules only and
never visits URLs. It does not verify dataset provenance or label quality:
the default 10 cases are regression examples, not a representative estimate
of real-world performance.

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
│   ├── test_scanner.py              # URL, validation, risk, and history tests
│   ├── test_message_scanner.py      # Message scanner unit tests
│   ├── test_cli.py                  # CLI input and cancellation behavior
│   ├── test_visualization.py        # Chart export regression
│   ├── test_storage.py              # Storage privacy and retention tests
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
