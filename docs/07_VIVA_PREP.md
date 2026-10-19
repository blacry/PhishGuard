# 07 — Viva Preparation

These are the questions you're most likely to get in a viva, with simple
answers tied directly to OUR code. Read these after you understand the code.

---

## General Questions

### Q1: What does your project do?
**A:** PhishGuard is a Python CLI tool that analyzes URLs and text messages
for phishing indicators. It uses rule-based static analysis — it checks the
STRUCTURE of a URL and the LANGUAGE of a message without ever opening or
visiting any links. It gives a risk score (0-100), classifies the threat
(LOW to CRITICAL), explains what triggered, and gives safety tips.

### Q2: Why did you choose this project?
**A:** Phishing is the #1 cyberattack method — over 80% of breaches start
with phishing. I wanted to build something that solves a real problem while
learning Python fundamentals like string manipulation, file handling, and
modular programming.

### Q3: What is phishing?
**A:** Phishing is when an attacker pretends to be a trusted entity (bank,
Google, etc.) to trick you into revealing passwords, credit card numbers,
or other sensitive information. It usually comes via email, SMS, or chat.

### Q4: Is your tool 100% accurate?
**A:** No. It uses heuristics (educated guesses), not machine learning.
It can produce false positives (flagging safe things) and false negatives
(missing phishing attempts). For example, a legitimate URL with "login"
in it might get a small score. A carefully crafted phishing email with
no keywords might slip through.

---

## Architecture Questions

### Q5: Explain your project structure.
**A:** The project has three main layers:
1. **Scanners** (`scanners/`) — check for phishing indicators
2. **Engine** (`engine/`) — calculate score, classify threat, generate explanation
3. **Utils** (`utils/`) — validate input, save to CSV, compute statistics

Data flows: User Input → Validation → Scanners → Engine → Display + Save.

### Q6: Why did you separate the code into multiple files?
**A:** This is called "separation of concerns." Each file has ONE job.
If I need to fix the scoring logic, I only change `risk_engine.py`. If I
add a new indicator, I only add a function in the scanner. This makes
the code easier to read, test, debug, and extend.

### Q7: What does `__init__.py` do?
**A:** It tells Python "this folder is a package that can be imported."
Without it, `from scanners import url_scanner` would fail. Our `__init__.py`
files also contain a docstring explaining what the package does.

### Q8: What does `if __name__ == "__main__"` mean?
**A:** When you run `python main.py`, Python sets `__name__` to `"__main__"`.
When another file imports `main.py`, `__name__` is set to `"main"`.
This check ensures `main()` only runs when you execute the file directly,
not when it's imported.

---

## Algorithm Questions

### Q9: How does your scoring work?
**A:** Each indicator has a weight (a number). When we scan a URL or message,
we check each indicator. If it triggers, we add its weight to a running total.
The total is capped at 100 using `min(total, 100)`. Then we classify:
0-24 = LOW, 25-49 = MEDIUM, 50-74 = HIGH, 75-100 = CRITICAL.

### Q10: Why do you cap the score at 100?
**A:** Without capping, a URL that triggers everything could score 105 or
more. A score of 200 doesn't mean "twice as phishy as 100." Capping keeps
the scale simple and intuitive for users.

### Q11: How did you choose the weights?
**A:** The weights are heuristics — educated guesses based on how phishing
typically works. Credential requests (weight 25) are more suspicious than
a missing HTTPS (weight 10) because no legit company asks for passwords
via email. Different experts might choose different weights.

### Q12: How do you avoid double-counting?
**A:** URL indicators check the URL string. Message indicators check the
message text. If a message contains a URL, we scan them separately. The
`suspicious_url_words` category has low weight (5) because words like
"login" appear in legit URLs too, while `credential_request` in messages
has high weight (25) because asking for passwords in text is almost
always phishing.

---

## Python Questions

### Q13: What is `try/except` and where do you use it?
**A:** `try/except` catches errors so the program doesn't crash. In
`get_user_choice()`, if the user types "abc" instead of a number,
`int("abc")` would crash with a ValueError. We catch that error and
return -1 instead, so the menu just says "invalid choice."

### Q14: What is a dictionary and where do you use it?
**A:** A dictionary stores key-value pairs like `{"name": "PhishGuard"}`.
We use dicts everywhere: each indicator result is a dict with keys like
`indicator`, `triggered`, `detail`. The `INDICATOR_WEIGHTS` dictionary
maps indicator names to their numeric weights.

### Q15: Explain the `while True` loop in main.py.
**A:** `while True` creates an infinite loop — it runs forever. We use
`break` to stop it when the user picks option 5 (Exit). This is a common
pattern for CLI menus because we don't know in advance how many times
the user will want to use the menu.

### Q16: What is a regular expression (regex)?
**A:** A regex is a pattern that describes a set of strings. For example,
`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` matches IP addresses like
`192.168.1.1`. We use the `re` module in Python to match these patterns
in URLs and messages.

### Q17: What is the difference between `"a"` and `"w"` file modes?
**A:** `"w"` (write) erases the file and writes from scratch. `"a"` (append)
adds to the end without erasing. We use `"a"` for scan_history.csv so
previous scans are preserved.

---

## Testing Questions

### Q18: How do you test your code?
**A:** We use pytest. Each test function checks one specific behavior.
For example, `test_check_https_detects_http` verifies that an HTTP URL
triggers the HTTPS indicator. We use `assert` to check expected vs actual
results. Run with: `pytest tests/test_scanner.py -v`.

### Q19: What is a false positive? A false negative?
**A:** False positive: flagging something safe as phishing (e.g., a long
legitimate URL). False negative: missing actual phishing (e.g., a
well-crafted phishing email with no keywords). Both are limitations of
our heuristic approach.

---

## Design Decision Questions

### Q20: Why CLI and not a GUI?
**A:** CLI is simpler to build and debug. It focuses on the logic, not
the interface. The project scope is about the detection algorithm, not
UI design. A GUI could be a future enhancement.

### Q21: Why don't you actually visit the URL?
**A:** That would be dangerous. The URL might host malware, track visitors,
or exploit browser vulnerabilities. Static analysis (looking at the URL
string) is safe and sufficient for our heuristic approach.

### Q22: Why CSV instead of a database?
**A:** CSV is human-readable, requires no setup, and can be opened in
Excel. For a small project, it's simpler than SQLite. pandas can read
CSVs easily for statistics and visualization.
