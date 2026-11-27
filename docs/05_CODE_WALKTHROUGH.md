# 05 — Code Walkthrough

This document explains every module and function in PhishGuard. For each one,
you'll find: what it does, what Python concepts it uses, and what its inputs
and outputs are. This is your study guide for the viva.

---

## main.py — The Entry Point

**Purpose:** This is the file you run (`python main.py`). It shows a menu,
reads the user's choice, and calls the right function.

| Function | Purpose | Inputs | Outputs | Python Concepts |
|----------|---------|--------|---------|-----------------|
| `display_banner()` | Print the welcome header | None | Prints to screen | `print()`, string multiplication (`"=" * 55`) |
| `display_menu()` | Print the 6 menu options | None | Prints to screen | `print()` |
| `_read_prompt(prompt)` | Read input; treat EOF/Ctrl+C as cancellation | Prompt text | `str` or `None` | `input()`, `try/except` |
| `get_user_choice()` | Read and validate the user's menu choice | None (reads from keyboard) | `int` (1-6), `-1` on invalid input, or `None` on interruption | input helper, `int()`, `strip()` |
| `handle_url_scan()` | Run static checks plus optional reputation lookup | None | Prints report and stores metadata | scanner calls, risk engine |
| `handle_message_scan()` | Scan text and embedded URLs | None | Prints report and stores metadata | scanner calls, loops |
| `handle_delete_history()` | Confirm and delete stored scan rows | None | Prints deletion result | input validation, SQLite |
| `main()` | The menu loop — runs until the user exits or input ends | None | None | `while True`, `if/elif/else`, `break`, function calls |

**Key pattern:** `if __name__ == "__main__": main()`
- This line checks: "Am I being run directly, or imported?"
- If you run `python main.py`, it executes `main()`.
- If another file does `import main`, it does NOT run `main()`.
- This is a Python best practice.

---

## scanners/url_scanner.py — URL Analysis

**Purpose:** Check a URL's structure for phishing red flags.
Never opens the URL — only looks at the text.

| Function | Purpose | Inputs | Outputs | Python Concepts |
|----------|---------|--------|---------|-----------------|
| `check_https(url)` | Check for HTTPS vs HTTP | `url: str` | `dict` with indicator, triggered, detail | `str.startswith()`, dictionary creation |
| `check_ip_address(url)` | Detect raw IP addresses | `url: str` | `dict` | Regular expressions (`re` module), `re.search()` |
| `check_url_length(url)` | Flag unusually long URLs | `url: str` | `dict` | `len()`, comparison operators |
| `check_subdomains(url)` | Count and flag excess subdomains | `url: str` | `dict` | `str.split(".")`, `len()`, string parsing |
| `check_suspicious_keywords(url)` | Match against keyword list | `url: str` | `dict` with matched_keywords list | `for` loop, `str.lower()`, `in` operator, lists |
| `check_special_characters(url)` | Detect @, excess // | `url: str` | `dict` with found_characters list | `in` operator, character checking |
| `scan_url(url)` | Run ALL checks, return results | `url: str` | `list[dict]` | Function calls, list building |

---

## scanners/message_scanner.py — Message Analysis

**Purpose:** Detect phishing language patterns in text messages.

| Function | Purpose | Inputs | Outputs | Python Concepts |
|----------|---------|--------|---------|-----------------|
| `extract_urls(message)` | Find URLs embedded in text | `message: str` | `list[str]` | `re.findall()`, regex patterns |
| `detect_urgency(message)` | Find panic-inducing language | `message: str` | `dict` with matched_words | Loop over keyword list, `str.lower()`, `in` |
| `detect_threat_language(message)` | Find threatening phrases | `message: str` | `dict` with matched_words | Same pattern as urgency |
| `detect_credential_request(message)` | Find password/identity requests | `message: str` | `dict` with matched_words | Same pattern |
| `detect_financial_request(message)` | Find money/payment requests | `message: str` | `dict` with matched_words | Same pattern |
| `scan_message(message)` | Run ALL checks + extract URLs | `message: str` | `dict` with indicators + URLs | Function calls, dict construction |

---

## engine/risk_engine.py — Scoring and Classification

**Purpose:** Turn raw indicator results into a risk score and threat label.

| Function | Purpose | Inputs | Outputs | Python Concepts |
|----------|---------|--------|---------|-----------------|
| `calculate_risk_score(indicator_results)` | Sum weights of triggered indicators, cap at 100 | `list[dict]` | `int` (0-100) | `for` loop, dictionary lookup, `min()`, accumulator pattern |
| `classify_threat(risk_score)` | Map score to LOW/MEDIUM/HIGH/CRITICAL | `int` | `str` | `if/elif/else`, comparison operators |
| `classify_with_reputation(risk_score, results)` | Keep heuristic score separate; elevate a fresh exact feed match | `int`, `list[dict]` | `str` | separate signal handling |

**Key data:** `INDICATOR_WEIGHTS` — a dictionary mapping indicator names
to their numeric weights. Defined at module level (not inside a function).

---

## engine/recommendation_engine.py — Explanations and Advice

**Purpose:** Generate human-readable output from scan results.

| Function | Purpose | Inputs | Outputs | Python Concepts |
|----------|---------|--------|---------|-----------------|
| `generate_explanation(indicator_results)` | Build a text explaining what triggered | `list[dict]` | `str` (multi-line) | `for` loop, f-strings, string concatenation |
| `generate_recommendations(threat_level, indicator_results)` | Give safety tips based on threat | `str`, `list[dict]` | `list[str]` | `if/elif/else`, list creation |

---

## utils/validators.py — Input Validation

**Purpose:** Check if user input is valid before processing.

| Function | Purpose | Inputs | Outputs | Python Concepts |
|----------|---------|--------|---------|-----------------|
| `is_valid_url(text)` | Check if text looks like a URL | `str` | `bool` | `str.startswith()`, `in` operator, `bool` return |
| `is_valid_message(text)` | Check if text is worth scanning | `str` | `bool` | `len()`, `str.strip()`, `str.split()` |
| `sanitize_input(text)` | Clean up whitespace | `str` | `str` | `str.strip()` |

---

## scanners/reputation.py — Optional Phishing Feed

**Purpose:** Download and cache the OpenPhish Community Feed when explicitly
enabled, then compare normalized full URLs locally. The submitted URL is never
sent to the provider.

| Function | Purpose | Important behavior |
|----------|---------|--------------------|
| `parse_openphish_feed(contents)` | Validate/normalize feed entries | Accepts HTTP(S) URLs only |
| `lookup_url_reputation(url)` | Return disabled, listed, not-listed, stale, or unavailable status | 12-hour cache, 1-hour retry limit, 10-second network timeout |
| `summarize_reputation_results(results)` | Reduce results for scan history | Kept separate from static indicator scoring |

---

## utils/helpers.py — File I/O and Statistics

**Purpose:** Save scan metadata to SQLite and compute summary statistics.

| Function | Purpose | Inputs | Outputs | Python Concepts |
|----------|---------|--------|---------|-----------------|
| `save_scan(scan_result)` | Store scan metadata; encrypt input only when configured | `dict` | `bool` | `sqlite3`, Fernet encryption, retention |
| `delete_scan_history()` | Delete scan records and retain an audit event | None | `int` or `None` | SQLite transactions |
| `generate_statistics()` | Read history and compute stats | None | `dict` or `None` | `for` loop, `len()`, averages, counting |

---

## utils/charts.py — Chart Exports

**Purpose:** Render threat distribution and scan input-type charts from
SQLite history. It uses standard-library counters and matplotlib; pandas is
not required.

---

## Keyword Validation and Benchmark

- `utils/keywords.py` checks the CSV header, allowed categories, duplicate
  category/keyword pairs, non-empty descriptions, and positive weights before
  scanner code uses the data.
- `utils/benchmark.py` evaluates `data/test_cases.csv` and reports exact
  classification accuracy, binary alert precision/recall, false positives,
  false negatives, and a confusion matrix. Run it with
  `python -m utils.benchmark`. This small hand-authored regression set does
  not estimate real-world performance.
- `Dockerfile` and `compose.yaml` provide an interactive, non-root deployment
  with persistent data and chart volumes. The image excludes local scan
  databases and feed caches.
- `.github/workflows/ci.yml` runs tests and the local benchmark, then builds
  the container image for pushes and pull requests.

---

## Python Concepts Checklist

Every concept used in this project, for your viva reference:

| Concept | Where It's Used | Quick Explanation |
|---------|----------------|-------------------|
| `print()` | main.py | Display text on screen |
| `input()` | main.py | Read text from keyboard |
| `int()` | main.py | Convert string to integer |
| `try/except` | main.py, helpers.py | Catch errors without crashing |
| `while True` / `break` | main.py | Loop forever until break |
| `if/elif/else` | Everywhere | Make decisions |
| `functions` (def) | Everywhere | Reusable blocks of code |
| `return` | Everywhere | Send a value back from a function |
| `dictionaries` | Scanners, engine | Key-value pairs like `{"name": "value"}` |
| `lists` | Scanners, engine | Ordered collections like `[1, 2, 3]` |
| `str methods` | Scanners, validators | `.lower()`, `.strip()`, `.startswith()`, `.split()` |
| `for loops` | Scanners, engine, helpers | Repeat for each item in a list |
| `len()` | Scanners, validators | Count characters or items |
| `min()` | risk_engine.py | Find the smaller of two values |
| `f-strings` | recommendation_engine | Format strings with variables: `f"Score: {x}"` |
| `re` module | url_scanner, message_scanner | Pattern matching with regex |
| `sqlite3` module | helpers.py | Store and query local scan history |
| `cryptography.fernet` | helpers.py | Encrypt opt-in stored input |
| `csv` module | keywords.py, benchmark.py | Validate keyword data and read labeled cases |
| `import` | Everywhere | Use code from other modules |
| `__name__ == "__main__"` | main.py | Check if file is run directly |
| `docstrings` | Everywhere | Documentation inside `"""triple quotes"""` |
