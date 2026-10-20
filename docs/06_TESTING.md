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
pytest tests/test_scanner.py -v
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

All **28 test functions** are fully implemented and passing:
- 10 URL scanner tests
- 6 Message scanner tests
- 6 Risk & recommendation engine tests
- 3 Input validator tests
- 2 CSV history & statistics tests
- 1 Batch regression test for all 10 prebuilt cases in `data/test_cases.csv`

Run them anytime with:
```bash
python -m pytest -v
```

