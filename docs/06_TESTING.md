# 06 — Testing Strategy

## Why Test?

Testing makes sure your code does what you THINK it does. Without tests,
you might change one function and accidentally break another without knowing.
Tests catch this immediately.

We use **pytest**, a Python testing library. Test functions must start with
`test_` and use `assert` to check expected vs actual results.

---

## How to Run Tests

```bash
cd PhishGuard
python -m pip install -r requirements-dev.txt
python -m pytest -v
```

- `-v` means verbose: shows each test name and pass/fail.
- Green = passed. Red = failed. Yellow = skipped.

---

## Test Categories

### 1. URL Scanner Tests (test that each URL check works correctly)

| Test | What It Checks | Input | Expected |
|------|---------------|-------|----------|
| `test_check_https_detects_http` | HTTP triggers the indicator | `"http://example.com"` | `triggered: True` |
| `test_check_https_passes_https` | HTTPS does NOT trigger | `"https://example.com"` | `triggered: False` |
| `test_check_ip_address_detects_ip` | IP address triggers | `"http://192.168.1.1/login"` | `triggered: True` |
| `test_check_ip_address_passes_domain` | Normal domain does NOT trigger | `"http://example.com"` | `triggered: False` |
| `test_check_url_length_detects_long_url` | Long URL triggers | 80+ char URL | `triggered: True` |
| `test_check_url_length_passes_short_url` | Short URL does NOT trigger | `"https://example.com"` | `triggered: False` |
| `test_check_subdomains_detects_many` | 3+ subdomains triggers | `"http://a.b.c.example.com"` | `triggered: True` |
| `test_check_subdomains_passes_normal` | Normal URL does NOT trigger | `"https://www.example.com"` | `triggered: False` |
| `test_check_suspicious_keywords_detects` | Phishing keywords trigger | `"http://example.com/login"` | `triggered: True` |
| `test_check_special_characters_detects_at` | @ symbol triggers | `"http://google.com@evil.com"` | `triggered: True` |

### 2. Message Scanner Tests (test that each message check works correctly)

| Test | What It Checks | Input | Expected |
|------|---------------|-------|----------|
| `test_extract_urls_finds_url` | URL extraction works | `"Click http://example.com"` | `["http://example.com"]` |
| `test_extract_urls_empty_message` | No URLs returns empty list | `"Hello there"` | `[]` |
| `test_detect_urgency_finds_urgent` | Urgency words trigger | `"Act now immediately!"` | `triggered: True` |
| `test_detect_threat_language_finds_threat` | Threats trigger | `"Account will be suspended"` | `triggered: True` |
| `test_detect_credential_request_finds_request` | Credential asks trigger | `"Verify your password"` | `triggered: True` |
| `test_detect_financial_request_finds_request` | Financial asks trigger | `"Send wire transfer"` | `triggered: True` |

### 3. Risk Engine Tests (test scoring and classification)

| Test | What It Checks | Input | Expected |
|------|---------------|-------|----------|
| `test_classify_threat_low` | Score 0-24 = LOW | `10` | `"LOW"` |
| `test_classify_threat_medium` | Score 25-49 = MEDIUM | `30` | `"MEDIUM"` |
| `test_classify_threat_high` | Score 50-74 = HIGH | `60` | `"HIGH"` |
| `test_classify_threat_critical` | Score 75-100 = CRITICAL | `85` | `"CRITICAL"` |
| `test_risk_score_capped_at_100` | Score never exceeds 100 | Many triggered indicators | `<= 100` |

### 4. Validator Tests (test input validation)

| Test | What It Checks | Input | Expected |
|------|---------------|-------|----------|
| `test_is_valid_url_accepts_http` | Valid URLs accepted | `"http://example.com"` | `True` |
| `test_is_valid_url_rejects_garbage` | Random text rejected | `"not a url"` | `False` |
| `test_is_valid_message_rejects_empty` | Empty strings rejected | `""` | `False` |

### 5. Production-readiness regression tests

- `test_cli.py` verifies clean exit on EOF/Ctrl+C, invalid menu input handling,
  and that interrupted scan/delete prompts cancel without processing.
- `test_keywords.py` verifies the tracked keyword CSV and rejects duplicate or
  malformed entries.
- `test_reputation.py` uses a mocked feed response only; it checks URL
  normalization, caching, timeout behavior, and that lookup requests contain
  only the fixed feed URL—not the URL being scanned.
- `test_storage.py` covers history statistics, database migration, encryption
  defaults, retention, deletion, and removal of the retired storage metadata
  table while preserving existing scan rows.
- `test_benchmark.py` runs all labeled cases through the static rules.
- `test_visualization.py` verifies chart export from representative scan
  records without relying on pandas.

Run the local benchmark separately with:

```powershell
python -m utils.benchmark
```

This runs the 10-case hand-authored regression set. The evaluator also accepts
another labeled CSV:

```powershell
python -m utils.benchmark --dataset data\evaluation_cases.csv
```

The benchmark accepts the PhishGuard CSV header
`input_type,input,expected_threat_level,description` or UCI PhiUSIIL's URL
dataset columns `URL` and `label`. PhiUSIIL labels `0` as phishing and `1` as
legitimate; the evaluator treats any non-LOW classification as a phishing
alert. It also recognizes the prepared Kaggle PhishGuard CSV through its
explicit `Kaggle source label: benign` and `Kaggle source label: phishing`
description values. In each case it uses URL strings only, applies static
rules, and never visits URLs. Kaggle's source is the [Malicious URLs
dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset),
listed as CC0. This prepared sample contains unique, unambiguous benign and
phishing URLs; six conflicting-label URLs were excluded, as were malware and
defacement rows. The benchmark cannot independently verify the source labels,
sampling process, or representativeness.

The full UCI snapshot contains 235,795 rows. Our measured result was 60.4%
binary accuracy, 100% precision, 7.4% recall, 13.8% F1, zero false positives,
and 93,491 false negatives. This is a historical, source-specific result, not
a real-world performance guarantee. The dataset was donated to UCI in 2024
and is licensed CC BY 4.0:
[PhiUSIIL Phishing URL (Website)](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset).
Citation: Prasad, A. & Chandra, S. (2024), DOI
[10.1016/j.cose.2023.103545](https://doi.org/10.1016/j.cose.2023.103545).

The evaluator also places hostnames into a deterministic 80% development /
20% holdout split using SHA-256. The current score cutoff (25) produced 13.3%
holdout F1 with no false positives. Selecting the best F1 cutoff on the
development split chose 5; on holdout that produced 77.3% F1, 64.3% recall,
97.0% precision, and a 1.5% false-positive rate (396 false positives and
6,995 false negatives). This threshold is only reported for analysis and has
not been applied to PhishGuard. The source dataset has a much higher phishing
share than typical user traffic, so its precision is not a production
estimate.

To show how prevalence affects precision, the evaluator also projects
precision for the development-selected cutoff at illustrative phishing
prevalences of 0.1%, 1%, 5%, and 10%, using holdout recall and false-positive
rate as point estimates. At 1% assumed prevalence, the candidate's projected
precision is about 30%, rather than its 97% measured precision on PhiUSIIL.
These are sensitivity scenarios, not measurements of actual traffic; they
assume the holdout's class-conditional rates carry over to the chosen
prevalence.

For the prepared Kaggle corpus (522,160 URLs: 428,074 benign and 94,086
phishing), the current cutoff of 25 produced 65.3% accuracy, 10.5% precision,
12.2% recall, 11.3% F1, and 23.0% false-positive rate (98,370 false positives
and 82,597 false negatives). The hostname-grouped split held out 103,259 URLs
and used 418,901 for development. Development-only F1 selection chose cutoff
0 (30.6% development F1, 100% development false-positive rate); on holdout it
flagged every URL, giving 18.0% precision, 100% recall,
30.5% F1, and 100% false-positive rate (84,701 false positives, no false
negatives). The unchanged cutoff 25 had 10.8% holdout precision, 12.2% recall,
11.5% F1, and 22.1% false-positive rate (18,739 false positives and 16,285
false negatives). The cutoff 0 result is not a useful selective detector and
remains analysis only. Any prevalence projections printed for this candidate
are illustrative calculations, not production forecasts.

The source is Kaggle's [Malicious URLs
dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset),
listed as CC0. The prepared data includes only unique, unambiguous benign and
phishing URLs; six conflicting-label URLs were excluded, as were malware and
defacement rows. These counts and metrics describe this prepared sample only.

The tool does not verify an arbitrary dataset's provenance or label quality.
The default 10-case set remains hand-authored regression coverage, not
representative evidence. Keep evaluation data separate from any data used to
change rules, and document its source, license, and labeling method.

The default 10-case set's 100% exact-label result is not representative
evidence of real-world precision or recall.

---

## Test Design Principles

1. **One test, one thing.** Each test checks exactly ONE behavior.
2. **Use fictional URLs.** We NEVER use real malicious URLs in tests.
   Always use `example.com` or made-up domains.
3. **Test both positive and negative cases.** Don't just test that "bad"
   input triggers — also test that "good" input does NOT trigger.
4. **Test boundary values.** For URL length, test at exactly 75 chars
   (should NOT trigger) and 76 chars (should trigger).

---

## Current Status

The suite includes URL and message scanners, risk classification, validation,
SQLite storage, keyword validation, reputation-feed behavior, benchmark
regressions, CLI input handling, and chart export. The exact pass count is
reported by pytest; run:

```bash
python -m pytest -v
```

The container definition can be built with `docker compose build` when Docker
is available. Tests remain in the development environment, not the runtime
image.

The local verification on 2026-11-27 passed all 60 tests, `compileall` for the
Python source/test directories, and `git diff --check`. These checks ran on the
current worktree.

`.github/workflows/ci.yml` defines test/benchmark and container-build jobs
locally. GitHub API verification on 2026-11-27 found no workflow file at
`.github/workflows/ci.yml` on the remote default branch (`master`, file lookup
returned 404) and zero Actions runs. Remote CI is therefore blocked pending
publication of the workflow. Docker Desktop, its Windows service, and the
Docker CLI are absent locally, so the image build is also blocked and remains
unverified.

