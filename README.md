# 🛡️ PhishGuard — Phishing Detection CLI Tool

> A Python command-line application that detects phishing indicators in URLs
> and text messages using rule-based static analysis.

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
6. **Saves** every scan to a CSV history for later review

⚠️ **Important:** PhishGuard uses static analysis only. It NEVER opens,
visits, or makes requests to submitted URLs.

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

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 💻 Usage

```bash
python main.py
```

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
  5. Exit
------------------------------
Enter your choice (1-5):
```

---

## 📁 Project Structure

```
PhishGuard/
├── main.py                          # CLI entry point (menu loop)
├── scanners/
│   ├── __init__.py
│   ├── url_scanner.py               # URL phishing checks (6 indicators)
│   └── message_scanner.py           # Message language checks (4 indicators)
├── engine/
│   ├── __init__.py
│   ├── risk_engine.py               # Scoring + threat classification
│   └── recommendation_engine.py     # Explanations + safety tips
├── utils/
│   ├── __init__.py
│   ├── validators.py                # Input validation (is it a URL?)
│   └── helpers.py                   # CSV save/load, statistics
├── data/
│   ├── keywords.csv                 # Phishing keyword database
│   ├── test_cases.csv               # Pre-built test inputs
│   └── scan_history.csv             # Saved scan results (append-only)
├── tests/
│   └── test_scanner.py              # pytest unit tests
├── docs/                            # Full project documentation
├── reports/                         # Generated reports
├── visualizations/                  # Generated charts
├── screenshots/                     # App screenshots
├── requirements.txt                 # Python dependencies
├── .gitignore                       # Git ignore rules
├── LICENSE                          # MIT License
└── README.md                        # This file
```

---

## 🧪 Running Tests

```bash
pytest tests/test_scanner.py -v
```

---

## ⚠️ Limitations

- **Static analysis only** — cannot detect phishing pages that look
  identical to real sites (visual similarity).
- **Rule-based** — relies on heuristic weights, not machine learning.
  May produce false positives (safe things flagged) and false negatives
  (phishing things missed).
- **HTTPS misconception** — a site having HTTPS does NOT mean it's safe.
  Phishers use HTTPS too. Our HTTPS check has a low weight for this reason.
- **English only** — keyword detection works only for English text.
- **No real-time checks** — doesn't verify if a domain is on a blacklist
  or check DNS records.

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
