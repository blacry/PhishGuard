# 02 — Architecture

## What is "Architecture"?

Architecture is the blueprint of your software. Just like a building has rooms
for different purposes (kitchen, bedroom, bathroom), software has modules for
different tasks. Good architecture means each piece has ONE clear job.

---

## The Big Picture

PhishGuard follows a simple pipeline: **Analyze → Score → Explain → Educate**.

```
User Input (URL or Message)
        │
        ▼
┌─────────────────┐
│   main.py       │  ← The receptionist: takes input, routes to scanners
│   (CLI Menu)    │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────┐
│         SCANNERS                │
│  url_scanner.py    │  message_  │  ← Detectives: check each indicator
│  (6 URL checks)   │  scanner   │
│                    │  (4 msg    │
│                    │  checks)   │
└────────┬───────────┴────────────┘
         │ list of indicator results
         ▼
┌─────────────────────────────────┐
│          ENGINE                 │
│  risk_engine.py                 │  ← The judge: calculates score + level
│  (score + classify)             │
│                                 │
│  recommendation_engine.py       │  ← The teacher: explains + advises
│  (explain + recommend)          │
└────────┬────────────────────────┘
         │ final results
         ▼
┌─────────────────────────────────┐
│          UTILS                  │
│  helpers.py (save to SQLite)    │  ← The clerk: saves records
│  validators.py (check input)    │  ← The bouncer: validates input
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│  data/scan_history.sqlite3      │  ← Local database; content is redacted by default
└─────────────────────────────────┘
```

The optional `reputation.py` feed checker runs separately from static scanner
indicators. It downloads feed data only and performs exact URL matching locally.

---

## Data Flow (Step by Step)

1. **User starts the app** → `main.py` shows the menu and handles EOF or
   Ctrl+C without an unhandled traceback.
2. **User picks option 1 (URL)** → `main.py` reads the URL.
3. **Validation** → `validators.py` checks if it's actually a URL.
4. **Scanning** → `url_scanner.scan_url()` runs all 6 checks.
   Each check returns a dict: `{indicator, triggered, detail}`.
5. **Optional reputation** → `reputation.lookup_url_reputation()` checks
    an exact URL against a locally cached OpenPhish feed. It downloads feed
    data only; the submitted URL is not sent to the provider.
6. **Scoring** → `risk_engine.calculate_risk_score()` adds up weights
   of triggered indicators. Caps at 100.
7. **Classification** → `risk_engine.classify_with_reputation()` keeps the
    heuristic score separate and raises a fresh exact feed match to CRITICAL.
8. **Explanation** → `recommendation_engine.generate_explanation()` builds
   a human-readable text from the triggered indicators.
9. **Recommendations** → `recommendation_engine.generate_recommendations()`
   picks safety tips based on the threat level.
10. **Display** → `main.py` prints static and reputation results separately.
11. **Save** → `helpers.save_scan()` stores scan metadata in SQLite. Input
    content is omitted unless a Fernet encryption key is configured.

---

## What Each Folder Does

| Folder | Purpose | Analogy |
|--------|---------|---------|
| `scanners/` | Check for phishing indicators | Detectives investigating clues |
| `engine/` | Score, classify, explain, recommend | Judge + Teacher |
| `utils/` | Validate input, save files, statistics | Admin assistants |
| `data/` | Keyword lists, test cases, history | Filing cabinet |
| `tests/` | Verify our code works correctly | Quality inspectors |
| `docs/` | Documentation for humans | User manual |
| `reports/` | Exported scan reports | Printed receipts |
| `visualizations/` | Chart images | Infographics |
| `screenshots/` | App screenshots for docs | Photos of the app |

---

## What Each File Does

| File | Purpose |
|------|---------|
| `main.py` | CLI menu, input routing, cancellation, display results |
| `scanners/url_scanner.py` | 6 URL structural checks |
| `scanners/message_scanner.py` | 4 message language checks + URL extraction |
| `engine/risk_engine.py` | Weighted score calculation + threat classification |
| `engine/recommendation_engine.py` | Human-readable explanations + safety tips |
| `utils/validators.py` | Input validation (is it a URL? is it a message?) |
| `utils/helpers.py` | SQLite history, retention, deletion, audit records, statistics |
| `utils/charts.py` | Threat-level and scan-type chart exports |
| `utils/keywords.py` | Keyword CSV validation and loading |
| `utils/benchmark.py` | Reproducible local classification metrics |
| `scanners/reputation.py` | Optional cached exact-URL reputation lookup |
| `data/keywords.csv` | Phishing keyword database with categories and weights |
| `data/test_cases.csv` | Pre-built inputs with expected results for testing |
| `data/openphish_cache.json` | Ignored local cache of public phishing-feed data |
| `data/scan_history.sqlite3` | Local scan history and content-free audit events |
| `tests/test_scanner.py` | URL, validation, risk, and history tests |
| `tests/test_message_scanner.py` | Message-language and URL-extraction tests |
| `tests/test_storage.py` | SQLite privacy, retention, and schema-migration tests |
| `tests/test_reputation.py` | Offline tests with mocked feed responses |
| `tests/test_keywords.py` | Keyword CSV validation tests |
| `tests/test_benchmark.py` | Labeled-case evaluation tests |
| `.github/workflows/ci.yml` | Automated tests, benchmark, and image build |

## Container Deployment

`Dockerfile` installs runtime dependencies and runs PhishGuard as a non-root
user. `compose.yaml` keeps the CLI interactive and stores the SQLite database,
feed cache, and exported charts in named volumes. The image exposes no ports.
`.dockerignore` excludes local scan history and runtime caches from the build
context. Scan history is SQLite-only; the previous CSV migration was removed.

GitHub Actions runs the test suite and benchmark on pushes, pull requests, or
manual requests, and builds the Docker image as a separate CI job. The
workflow is described in `.github/workflows/ci.yml`; YAML is a human-readable
configuration format, not a language used by the PhishGuard application.

---

## Why This Structure?

1. **Separation of concerns** — each module does ONE thing. If we need to fix
   the scoring logic, we only touch `risk_engine.py`, not everything.
2. **Testability** — small functions are easy to test in isolation.
3. **Readability** — a new reader can understand the project by reading
   the folder names.
4. **Extensibility** — adding a new indicator means adding one function
   in the scanner, one weight in the engine. Nothing else changes.
