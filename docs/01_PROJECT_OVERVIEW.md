# 01 — Project Overview

## The Problem

Phishing is one of the most common cyberattacks in the world. Attackers send
fake emails, SMS, or chat messages that look like they come from trusted
companies (banks, Google, Amazon). These messages trick people into:
- Clicking malicious links
- Entering their passwords on fake websites
- Sending money to the attacker

Phishing is a common way attackers try to steal information or money.
Even tech-savvy people can be fooled by convincing messages.

**The core question our project answers:**
> "Given a URL or a text message, how likely is it to be a phishing attempt?"

---

## Project Objectives

1. **Detect** phishing indicators in URLs and text messages.
2. **Score** the risk using a weighted, explainable system (0–100).
3. **Classify** the threat level (LOW, MEDIUM, HIGH, CRITICAL).
4. **Explain** why each indicator fired — don't just say "danger", say WHY.
5. **Educate** the user with safety recommendations.
6. **Log** scan metadata to SQLite; submitted input is redacted by default.
7. **Optionally check** exact URLs against a cached public phishing feed.

---

## Scope: What PhishGuard Does and Doesn't Do

### ✅ In Scope (MVP — Minimum Viable Product)
- URL structural analysis (HTTPS, IP, length, subdomains, keywords, special chars)
- Message language analysis (urgency, threats, credential requests, financial requests)
- Weighted risk scoring with a 0–100 capped scale
- 4-tier threat classification
- Human-readable explanations for each indicator
- Safety recommendations based on threat level
- SQLite scan history with timestamps, retention, and audit events
- Optional OpenPhish Community Feed lookups with local caching
- Keyword CSV schema validation
- Local statistics and Matplotlib chart exports
- CLI menu interface
- Graceful handling of interrupted prompts and end-of-input
- Automated CI tests, benchmark, and Docker image build

### 🔮 Stretch Goals (if time permits)
- PDF report export
- Batch scanning from a file
- Obtain an independently labeled evaluation corpus and measure
  false-positive/false-negative rates with it

### ❌ Out of Scope
- Machine learning or AI-based detection
- Actually visiting or opening URLs (this is UNSAFE)
- Automatically browsing or opening submitted URLs
- GUI (graphical interface) — we use CLI
- Multi-language support (English only for v1)
- Browser extension

---

## Technology Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| Language | Python 3.x | Required by course; great for string manipulation |
| Data handling | Python `csv`, SQLite | CSV keyword loading and local scan history |
| Charts | matplotlib | Create visual summaries |
| Testing | pytest | Simple, powerful test framework |
| Deployment | Docker Compose | Reproducible interactive container with persistent volumes |
| Version control | git | Track changes, required for submission |

The OpenPhish feature is opt-in. It downloads the public feed; the URL being
scanned is matched locally and is not sent to the provider.

---

## How to Read This Documentation

These docs are written for a first-year student. They explain WHY, not just WHAT.
Every technical term is defined in [10_GLOSSARY.md](10_GLOSSARY.md). If you see
a word you don't know, check the glossary first.

Start here, then read the docs in order. By the end, you'll be able to explain
every line of code in a viva.
