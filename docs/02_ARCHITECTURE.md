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
│  helpers.py (save to CSV)       │  ← The clerk: saves records
│  validators.py (check input)    │  ← The bouncer: validates input
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│     data/scan_history.csv       │  ← The filing cabinet: stores results
└─────────────────────────────────┘
```

---

## Data Flow (Step by Step)

1. **User starts the app** → `main.py` shows the menu.
2. **User picks option 1 (URL)** → `main.py` reads the URL.
3. **Validation** → `validators.py` checks if it's actually a URL.
4. **Scanning** → `url_scanner.scan_url()` runs all 6 checks.
   Each check returns a dict: `{indicator, triggered, detail}`.
5. **Scoring** → `risk_engine.calculate_risk_score()` adds up weights
   of triggered indicators. Caps at 100.
6. **Classification** → `risk_engine.classify_threat()` maps score to label.
7. **Explanation** → `recommendation_engine.generate_explanation()` builds
   a human-readable text from the triggered indicators.
8. **Recommendations** → `recommendation_engine.generate_recommendations()`
   picks safety tips based on the threat level.
9. **Display** → `main.py` prints everything to the user.
10. **Save** → `helpers.save_scan()` appends a row to `scan_history.csv`.

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
| `main.py` | CLI menu, input routing, display results |
| `scanners/url_scanner.py` | 6 URL structural checks |
| `scanners/message_scanner.py` | 4 message language checks + URL extraction |
| `engine/risk_engine.py` | Weighted score calculation + threat classification |
| `engine/recommendation_engine.py` | Human-readable explanations + safety tips |
| `utils/validators.py` | Input validation (is it a URL? is it a message?) |
| `utils/helpers.py` | CSV save/load + statistics computation |
| `data/keywords.csv` | Phishing keyword database with categories and weights |
| `data/test_cases.csv` | Pre-built inputs with expected results for testing |
| `data/scan_history.csv` | Append-only log of all scan results |
| `tests/test_scanner.py` | pytest unit tests for all modules |

---

## Why This Structure?

1. **Separation of concerns** — each module does ONE thing. If we need to fix
   the scoring logic, we only touch `risk_engine.py`, not everything.
2. **Testability** — small functions are easy to test in isolation.
3. **Readability** — a new reader can understand the project by reading
   the folder names.
4. **Extensibility** — adding a new indicator means adding one function
   in the scanner, one weight in the engine. Nothing else changes.
