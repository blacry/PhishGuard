# 08 — Limitations and Future Work

## Current Limitations

### 1. False Positives (Flagging Safe Things)

| Scenario | Why It Happens |
|----------|----------------|
| Long legitimate URL (e.g., a Google search link) | Our length check triggers at 75+ chars, but many real URLs are long |
| URL with "login" in it (e.g., `https://accounts.google.com/login`) | "login" is a suspicious keyword, but Google's actual login page contains it |
| Legitimate urgent email (e.g., password reset you requested) | Urgency language detection can't tell if YOU asked for the email |

**Mitigation in v1:** We use LOW weights for ambiguous indicators (e.g.,
5 per keyword) and HIGH weights for strong signals (e.g., 25 for
credential requests). This reduces false positives but doesn't eliminate them.

### 2. False Negatives (Missing Real Phishing)

| Scenario | Why It Happens |
|----------|----------------|
| Well-crafted phishing email with no keywords | Our keyword list is finite; clever phishers avoid obvious words |
| Phishing page that looks identical to a real site | We only analyze text, not visual appearance |
| URL shorteners (bit.ly, tinyurl) | The shortened URL hides the real destination |
| Homograph attacks (using Cyrillic "а" instead of Latin "a") | We don't check for lookalike Unicode characters |

### 3. The HTTPS Misconception

This is important enough to highlight separately:

> **Having HTTPS does NOT mean a site is safe.**

HTTPS only means the connection is encrypted. It says nothing about whether
the site is legitimate. Phishers get free HTTPS certificates from Let's
Encrypt. Our HTTPS check has a LOW weight (10) for this reason — it's a
clue, not proof.

### 4. English Only

Our keyword lists are in English. Phishing messages in Hindi, Spanish,
or other languages would not be detected.

### 5. No Context Awareness

PhishGuard can't know:
- Whether you actually have an account with the company mentioned
- Whether you requested a password reset
- Whether the sender is who they claim to be
- Whether the domain is registered to a legitimate company

### 6. Static Keyword Matching

We use exact keyword matching. A phisher who writes "v3rify y0ur p@ssw0rd"
(with number substitutions) would bypass our checks.

---

## Future Work (What Could Be Added)

### Short-term (Could Do in This Course)

| Feature | Difficulty | Benefit |
|---------|-----------|---------|
| Matplotlib charts (pie chart of threat distribution) | Easy | Visual appeal for submission |
| PDF report export | Medium | Professional output |
| Batch scanning from a file | Easy | Scan many URLs at once |
| More keywords in keywords.csv | Easy | Better coverage |
| URL shortener detection | Easy | Flag bit.ly, tinyurl, etc. |

### Medium-term (Next Semester)

| Feature | Difficulty | Benefit |
|---------|-----------|---------|
| Domain age check via WHOIS API | Medium | New domains are suspicious |
| Domain reputation via VirusTotal API | Medium | Check against known blacklists |
| Typosquatting detection (googIe.com vs google.com) | Medium | Catch lookalike domains |
| SQLite database instead of CSV | Medium | Better for large datasets |
| GUI with Tkinter | Medium | More user-friendly |

### Long-term (Advanced / Out of Scope)

| Feature | Difficulty | Benefit |
|---------|-----------|---------|
| Machine learning classifier | Hard | Learn from data, adapt to new phishing |
| Browser extension | Hard | Real-time protection while browsing |
| Visual similarity analysis (screenshot comparison) | Hard | Catch clone pages |
| Multi-language support | Medium | Detect non-English phishing |
| Email header analysis (SPF, DKIM, DMARC) | Hard | Verify sender authenticity |

---

## Honest Assessment

PhishGuard v1 is an **educational tool**, not a production security product.
It teaches the principles of phishing detection — pattern matching, scoring,
classification — using beginner-friendly Python. It will catch obvious
phishing attempts but will miss sophisticated ones.

For real-world protection, use established tools like:
- Google Safe Browsing
- VirusTotal
- Your email provider's built-in phishing filter

PhishGuard complements these by teaching you HOW they think.
