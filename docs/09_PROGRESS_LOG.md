# 09 — Progress Log

This log tracks what was built, when, and why. Updated after every task.

---

## 2026-10-19 — Task 1 & 2: Project Skeleton + Documentation

### What Was Done
- Created the complete project folder structure:
  - `main.py` with a working CLI menu loop (5 options, crash-safe input)
  - `scanners/` package with `url_scanner.py` (6 function stubs) and
    `message_scanner.py` (5 function stubs + orchestrator)
  - `engine/` package with `risk_engine.py` (scoring + classification stubs)
    and `recommendation_engine.py` (explanation + recommendation stubs)
  - `utils/` package with `validators.py` (3 stubs) and `helpers.py` (2 stubs)
  - `data/` with `keywords.csv` (45 keywords in 6 categories),
    `test_cases.csv` (10 test inputs), and `scan_history.csv` (header only)
  - `tests/` with `test_scanner.py` (21 test stubs)
  - `reports/`, `visualizations/`, `screenshots/` (empty placeholder dirs)
  - `README.md`, `requirements.txt`, `.gitignore`, `LICENSE` (MIT)
- Created 10 documentation files in `docs/`
- Initialized git repository with first commit

### Decisions Made
1. **Weight values** — Chose weights based on how suspicious each indicator
   is in real-world phishing. IP addresses (25) weigh more than HTTPS (10)
   because IP-based URLs are rarer in legitimate sites.
2. **URL length threshold** — Set at 75 characters. This is a common
   heuristic; most legitimate URLs are shorter.
3. **Subdomain threshold** — Set at 3+ subdomains. `www.example.com` has
   1 subdomain (normal). `a.b.c.example.com` has 3 (suspicious).
4. **Keyword limit** — Max 3 keywords counted for `suspicious_keywords`
   (max 15 points) to prevent one check from dominating the score.
5. **File format** — CSV for simplicity. No database setup needed.
6. **Test URLs** — All fictional (`example.com`) or RFC-reserved IPs.
   Never use real malicious URLs.

### What's Next
- Task 3: Implement the URL scanner detection logic (Completed below)
- Task 4: Implement the message scanner detection logic
- Task 5: Implement the risk engine and recommendation engine
- Task 6: Connect everything in main.py
- Task 7: Implement tests, statistics, and visualizations

---

## 2026-10-19 — Task 3: URL Scanner & Validator Logic Implemented

### What Was Done
- **`utils/validators.py`**:
  - Implemented `sanitize_input()` using `strip()` to clean whitespace safely.
  - Implemented `is_valid_url()` using `urllib.parse.urlparse` to ensure valid domain structure and dot presence.
  - Implemented `is_valid_message()` to ensure non-empty input with at least 2 words and 5 characters.
- **`scanners/url_scanner.py`**:
  - Implemented `check_https()`: flags HTTP URLs as unencrypted.
  - Implemented `check_ip_address()`: detects IPv4 address hostnames using regex.
  - Implemented `check_url_length()`: flags URLs exceeding the 75-character threshold.
  - Implemented `check_subdomains()`: counts dots in hostnames and flags 3+ subdomains.
  - Implemented `check_suspicious_keywords()`: dynamic loading from `data/keywords.csv` with fallback defaults.
  - Implemented `check_special_characters()`: detects `@` symbol redirection and abnormal `//` occurrences.
  - Implemented `scan_url()`: orchestrates all 6 checks and returns structured results.
- **`tests/test_scanner.py`**:
  - Implemented full unit tests for all URL checks and validator functions.
  - Ran pytest: all 24 test cases passing.

### Decisions Made
1. **Fallback Keywords**: If `data/keywords.csv` is missing or unreadable, `url_scanner.py` seamlessly falls back to hardcoded defaults so the program never crashes.
2. **Subdomain Calculation**: Raw IP addresses are skipped from subdomain counts, preventing false triggers.
3. **URL Obfuscation Characters**: Targeted `@` (which redirects credentials to an alternate host) and double slashes `//` within paths/queries.

---

## 2026-10-19 — Task 4: Message Scanner Detection Logic Implemented

### What Was Done
- **`scanners/message_scanner.py`**:
  - Implemented `extract_urls()`: uses regex pattern `https?://[^\s<>\"']+` and strips trailing punctuation like `.` and `,` so trailing sentence punctuation isn't attached to URLs.
  - Implemented `detect_urgency()`: matches urgency terms (e.g., 'act now', 'within 24 hours') loaded dynamically from `data/keywords.csv`.
  - Implemented `detect_threat_language()`: matches threats of suspension, legal action, and lockouts.
  - Implemented `detect_credential_request()`: flags phrases soliciting passwords, identity confirmations, or credential verifications.
  - Implemented `detect_financial_request()`: catches requests for bank accounts, wire transfers, and gift cards.
  - Implemented `scan_message()`: central coordinator executing all 4 linguistic checks and extracting URLs for dual analysis.
- **`data/keywords.csv`**:
  - Expanded threat and credential terms to include common phrasings such as 'suspended', 'locked', and 'click here to verify'.
- **`tests/test_scanner.py`**:
  - Implemented unit tests for all message scanner functions.
  - All 24 unit tests passing.

### Decisions Made
1. **URL Punctuation Cleaning**: When a message ends with `"Visit http://example.com."`, trailing dots/commas are stripped using `.rstrip(".,;:!?)")` so the extracted URL remains clean.
2. **Resilience to Missing Files**: Added per-category fallback keyword dictionaries so the message scanner remains fully operational even if the CSV keyword database is absent.

---

## 2026-10-19 — Task 5: Risk Engine & Recommendation Engine Implemented

### What Was Done
- **`engine/risk_engine.py`**:
  - Defined `INDICATOR_WEIGHTS` dictionary reflecting our documented heuristic values (e.g., 25 for raw IP, 25 for credential request, 10 for HTTP).
  - Implemented `calculate_risk_score()`: iterates through triggered indicators, applies per-keyword multiplier for `suspicious_keywords` (5 pts per word up to 3 words = 15 pts max), and caps total score at 100 via `min(total, 100)`.
  - Implemented `classify_threat()`: maps scores to the 4 discrete tiers: LOW (0-24), MEDIUM (25-49), HIGH (50-74), CRITICAL (75-100).
- **`engine/recommendation_engine.py`**:
  - Implemented `generate_explanation()`: translates triggered indicator results into human-readable descriptions prefixed with clean ASCII markers for cross-platform terminal compatibility.
  - Implemented `generate_recommendations()`: provides tiered actionable advice (LOW through CRITICAL) plus contextual tips when specific high-severity indicators (like credential theft or IP addresses) trigger.
- **`tests/test_scanner.py`**:
  - Implemented unit tests for threat tier classification boundaries, capping logic at 100, and explanation/recommendation generation.
  - All 25 unit tests passing.

### Decisions Made
1. **Explainable Output Over Raw Numbers**: Prioritized plain-English breakdown with user-friendly indicator names over numeric weights alone.
2. **Dynamic Keyword Capping**: Suspicious keywords in URLs scale by count (5 per keyword up to 3) to prevent multiple common words from overwhelming the score single-handedly.
3. **Cross-Platform ASCII Formatting**: Used `[!]` and `[*]` markers rather than unicode emojis to ensure reliable rendering in default Windows consoles (cp1252).

---

## 2026-10-19 — Task 6: CLI & CSV History Integration (main.py + helpers.py)

### What Was Done
- **`utils/helpers.py`**:
  - Implemented `save_scan()`: appends new scans to `data/scan_history.csv` with automated timestamps and input sanitization (newlines replaced, strings truncated at 80 chars for clean CSV layout).
  - Implemented `load_scan_history()`: reads records using `csv.DictReader` and returns structured dictionaries.
  - Implemented `generate_statistics()`: computes total scans, counts by input type (URL vs. message), average risk score, and threat distribution counts.
- **`main.py`**:
  - Connected Option 1 (`handle_url_scan()`): prompts user -> validates -> scans -> calculates risk -> classifies threat -> displays structured report with recommendations -> logs to history.
  - Connected Option 2 (`handle_message_scan()`): prompts user -> validates message -> analyzes linguistic patterns -> extracts embedded URLs and scans their structure -> calculates combined risk -> explains & recommends -> logs to history.
  - Connected Option 3 (`handle_view_history()`): displays the 10 most recent scans in a structured tabular ASCII layout.
  - Connected Option 4 (`handle_statistics()`): renders summary metrics and an ASCII bar graph depicting threat distribution percentages.
- **`tests/test_scanner.py`**:
  - Added unit tests for CSV scan saving, history loading, and statistics generation.
  - All 27 unit tests passing.

### Decisions Made
1. **Dual Scanning for Messages**: When a message contains URLs, PhishGuard performs both linguistic analysis on the text AND structural analysis on the extracted links, combining indicators into an overall risk score.
2. **Terminal-Friendly Table & ASCII Chart**: Built formatted table views and horizontal bar charts using pure string manipulation (`"#" * bars`), ensuring zero reliance on complex GUI or web dependencies for core operation.
3. **Automatic Timestamping**: If callers omit a timestamp, `helpers.save_scan()` automatically stamps current local time (`YYYY-MM-DD HH:MM:SS`).




