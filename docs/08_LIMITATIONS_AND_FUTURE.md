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

### 7. Optional reputation feed limitations

The OpenPhish Community Feed is opt-in and cached locally for 12 hours.
PhishGuard compares the full normalized URL exactly, which can miss URL
variants and new campaigns. A fresh feed match is a separate signal, not
proof that a page is currently active or dangerous; absence from the feed is
never treated as proof of safety. Enabling feed refreshes makes outbound
requests to OpenPhish/GitHub, but does not transmit the URL being scanned.

### 8. Benchmark limitations

The included 10-case benchmark is hand-authored and closely aligned with the
rules. Its measured 100% exact-label agreement is useful as a regression
check only, not as a real-world false-positive or false-negative rate.
The benchmark can also evaluate UCI's external PhiUSIIL URL dataset. On its
235,795-row 2024 snapshot, PhishGuard's current rules achieved 60.4% binary
accuracy, 100% precision, 7.4% recall, 13.8% F1, zero false positives, and
93,491 false negatives. This shows a substantial recall gap on that dataset;
it does not predict performance on current traffic. The dataset is not bundled
in the repository, and the benchmark cannot verify arbitrary dataset
provenance, representativeness, or labels. Rule tuning must use a development
split and preserve an untouched holdout.

A hostname-grouped 80/20 experiment selected a score cutoff of 5 by
development-set F1. On the holdout, this candidate reached 77.3% F1 and 64.3%
recall, with 97.0% precision and a 1.5% false-positive rate (396 false
positives, 6,995 false negatives). The existing cutoff of 25 had 13.3% holdout
F1 and no false positives. The candidate is not enabled. The UCI dataset has
a much higher phishing prevalence than typical incoming user traffic, so the
measured precision may substantially overstate real-world precision.

The prepared Kaggle Malicious URLs sample contains 522,160 unique,
unambiguous benign/phishing URLs (428,074 benign and 94,086 phishing), after
excluding six conflicting-label URLs and all malware/defacement rows. At the
current cutoff of 25, it produced 10.5% precision, 12.2% recall, 11.3% F1,
23.0% false-positive rate, 98,370 false positives, and 82,597 false negatives.
In the hostname-grouped 80/20 split, F1 selection on development chose cutoff
0 (30.6% development F1, 100% development FPR); this alerts on every holdout
URL and yielded 18.0% precision, 100% recall,
30.5% F1, 100% false-positive rate, 84,701 false positives, and no false
negatives. At cutoff 25, holdout results were 10.8% precision, 12.2% recall,
11.5% F1, 22.1% false-positive rate, 18,739 false positives, and 16,285
false negatives. The candidate result illustrates that F1 selection alone
can favor an unusable all-alert threshold; it is not enabled.

The corpus is Kaggle's [Malicious URLs
dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset),
listed as CC0. The prepared sample's source labels and sampling process were
not independently audited. Its phishing prevalence is about 18%, so its
precision does not estimate deployment traffic. The benchmark's prevalence
projections are illustrative calculations from holdout recall/FPR, not
production forecasts.

The benchmark now reports illustrative precision projections at assumed
phishing prevalences of 0.1%, 1%, 5%, and 10%. For example, the candidate's
holdout recall/FPR point estimates project to about 30% precision at 1%
prevalence. These scenarios expose the base-rate effect; they are not a
replacement for evaluating labeled traffic from the intended deployment.
Public sources checked so far do not establish that natural prevalence:
[OpenPhish's free Community Feed](https://openphish.com/phishing_feeds.html)
is a phishing-only feed, while [Tranco](https://tranco-list.eu/) is a ranking
of popular domains, not a labeled sample of user-submitted URLs. A
privacy-reviewed, benign-heavy sample with reliable labels and a known
sampling method is still needed for deployment-relevant validation.

---

## Future Work (What Could Be Added)

### Short-term (Could Do in This Course)

| Feature | Difficulty | Benefit |
|---------|-----------|---------|
| PDF report export | Medium | Professional output |
| Batch scanning from a file | Easy | Scan many URLs at once |
| More keywords in keywords.csv | Easy | Better coverage |
| URL shortener detection | Easy | Flag bit.ly, tinyurl, etc. |

### Medium-term (Next Semester)

| Feature | Difficulty | Benefit |
|---------|-----------|---------|
| Add independently reviewed threat-intelligence providers | Medium | Broader, measured feed coverage |
| Typosquatting detection (googIe.com vs google.com) | Medium | Catch lookalike domains |
| Evaluate newer independent corpora and preserve a separate holdout for rule tuning | Medium | Check whether recall improves without introducing unacceptable false positives |
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

PhishGuard is still an **educational prototype**, not a production security
product. It combines explainable rules with an optional cached public feed,
but needs independent labeled-data evaluation, operational monitoring, and
broader threat-intelligence coverage before it can support production
decisions. CI verifies the regression suite and builds the container; this
does not replace deployment monitoring or an external security review.

For real-world protection, use established tools like:
- Google Safe Browsing
- VirusTotal
- Your email provider's built-in phishing filter

PhishGuard complements these by teaching you HOW they think.
