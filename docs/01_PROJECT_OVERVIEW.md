# 01 — Project Overview

## The Problem

Phishing is one of the most common cyberattacks in the world. Attackers send
fake emails, SMS, or chat messages that look like they come from trusted
companies (banks, Google, Amazon). These messages trick people into:
- Clicking malicious links
- Entering their passwords on fake websites
- Sending money to the attacker

According to reports, over **80% of data breaches** start with a phishing
attack. Even tech-savvy people fall for well-crafted phishing attempts.

**The core question our project answers:**
> "Given a URL or a text message, how likely is it to be a phishing attempt?"

---

## Project Objectives

1. **Detect** phishing indicators in URLs and text messages.
2. **Score** the risk using a weighted, explainable system (0–100).
3. **Classify** the threat level (LOW, MEDIUM, HIGH, CRITICAL).
4. **Explain** why each indicator fired — don't just say "danger", say WHY.
5. **Educate** the user with safety recommendations.
6. **Log** every scan to CSV for history and statistics.

---

## Scope: What PhishGuard Does and Doesn't Do

### ✅ In Scope (MVP — Minimum Viable Product)
- URL structural analysis (HTTPS, IP, length, subdomains, keywords, special chars)
- Message language analysis (urgency, threats, credential requests, financial requests)
- Weighted risk scoring with a 0–100 capped scale
- 4-tier threat classification
- Human-readable explanations for each indicator
- Safety recommendations based on threat level
- CSV scan history with timestamps
- CLI menu interface
- Basic statistics (count, averages, distribution)

### 🔮 Stretch Goals (if time permits)
- Matplotlib visualizations (pie charts, bar graphs of threat distribution)
- PDF report export
- Batch scanning from a file
- Domain age lookup (would need an API)

### ❌ Out of Scope
- Machine learning or AI-based detection
- Actually visiting or opening URLs (this is UNSAFE)
- Real-time domain reputation checks (needs internet API)
- GUI (graphical interface) — we use CLI
- Multi-language support (English only for v1)
- Browser extension

---

## Technology Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| Language | Python 3.x | Required by course; great for string manipulation |
| Data handling | pandas | Easy CSV read/write and statistics |
| Charts | matplotlib | Create visual summaries |
| Testing | pytest | Simple, powerful test framework |
| Version control | git | Track changes, required for submission |

---

## How to Read This Documentation

These docs are written for a first-year student. They explain WHY, not just WHAT.
Every technical term is defined in [10_GLOSSARY.md](10_GLOSSARY.md). If you see
a word you don't know, check the glossary first.

Start here, then read the docs in order. By the end, you'll be able to explain
every line of code in a viva.
