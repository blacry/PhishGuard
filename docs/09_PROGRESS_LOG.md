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
- Task 3: Implement the URL scanner detection logic
- Task 4: Implement the message scanner detection logic
- Task 5: Implement the risk engine and recommendation engine
- Task 6: Connect everything in main.py
- Task 7: Implement tests, statistics, and visualizations
