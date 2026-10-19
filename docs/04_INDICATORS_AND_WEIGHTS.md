# 04 — Indicators and Weights

## What is a "Heuristic Weight"?

A heuristic is a rule-of-thumb — a practical shortcut that works well
most of the time but isn't mathematically guaranteed. Our weights are
educated guesses about how suspicious each indicator is. They are NOT
trained from a dataset. A security expert might choose slightly different
numbers, and that's fine.

---

## How We Avoid Double-Counting

Some indicators overlap. For example, "login" could match both
`check_suspicious_keywords` (URL check) AND `detect_credential_request`
(message check). Here's how we handle this:

- **URL indicators and message indicators are separate checks.**
  URL keywords check the URL string only. Message checks scan the
  message text only (not embedded URLs).
- **`suspicious_url_words` in keywords.csv** has LOW weight (5 per word)
  because these words appear in legitimate URLs too.
- **`credential_request` in message scanner** has HIGH weight (20) because
  asking for passwords in a message is almost always phishing.
- **If a message contains a URL**, we scan the URL separately. The URL
  score and message score are combined, but they check different things
  in different places, so there's no double-counting.

---

## URL Indicators

| # | Indicator | Function | What It Checks | Why It Signals Phishing | Weight | Example |
|---|-----------|----------|----------------|------------------------|--------|---------|
| 1 | HTTPS Missing | `check_https` | Does the URL start with `http://` instead of `https://`? | HTTP sends data unencrypted. Legit login pages always use HTTPS. But phishers also use HTTPS now, so this alone is weak. | **10** | `http://example.com/login` |
| 2 | IP Address | `check_ip_address` | Is the domain a raw IP like `192.168.1.1`? | Legit sites use domain names. IPs hide the site's identity — you can't tell who owns `185.199.1.1`. | **25** | `http://192.168.1.1/secure` |
| 3 | Long URL | `check_url_length` | Is the URL longer than 75 characters? | Phishers pad URLs with fake paths and parameters to confuse victims and hide the real domain. | **15** | `http://example.com/very/long/path/with/many/segments/to/confuse` |
| 4 | Excessive Subdomains | `check_subdomains` | Are there 3+ subdomains (dots before the main domain)? | `login.google.security.evil.com` looks like Google but belongs to `evil.com`. Extra subdomains are a masking trick. | **20** | `http://secure.login.bank.example.com` |
| 5 | Suspicious Keywords | `check_suspicious_keywords` | Does the URL contain words like "login", "verify", "secure", "account"? | These words are crammed into phishing URLs to seem trustworthy. Weight is PER keyword, max 3 counted. | **5 each (max 15)** | `http://example.com/secure-login-verify` |
| 6 | Special Characters | `check_special_characters` | Does the URL contain `@` or extra `//` after the protocol? | `@` in a URL redirects the browser — `http://google.com@evil.com` goes to `evil.com`. Extra `//` can confuse URL parsers. | **20** | `http://google.com@evil.com/login` |

**Maximum possible URL score:** 10 + 25 + 15 + 20 + 15 + 20 = **105** → capped to **100**

---

## Message Indicators

| # | Indicator | Function | What It Checks | Why It Signals Phishing | Weight | Example |
|---|-----------|----------|----------------|------------------------|--------|---------|
| 7 | Urgency Language | `detect_urgency` | Words like "act now", "immediately", "expires", "urgent" | Creates panic so you act without thinking. Legitimate companies rarely use this pressure. | **15** | "Act now or your account expires in 24 hours!" |
| 8 | Threat Language | `detect_threat_language` | Words like "suspended", "legal action", "will be locked" | Fear of consequences makes victims comply. Real companies don't threaten via SMS. | **20** | "Your account will be suspended unless you verify immediately." |
| 9 | Credential Request | `detect_credential_request` | Phrases like "verify your password", "confirm your identity" | No legitimate company asks for passwords via email/SMS. This is the hallmark of phishing. | **25** | "Please verify your password by clicking the link below." |
| 10 | Financial Request | `detect_financial_request` | Phrases like "send payment", "wire transfer", "bank account", "gift card" | Directly targets your money. Gift card requests are a classic scam pattern. | **25** | "Please send a wire transfer to resolve this issue." |

**Maximum possible message score:** 15 + 20 + 25 + 25 = **85**  
**With embedded URL (max URL score):** 85 + 100 = **185** → capped to **100**

---

## Weight Rationale Summary

| Weight Range | Meaning | Indicators |
|-------------|---------|------------|
| 5 | Very low — common in legit context too | Individual URL keywords |
| 10 | Low — a clue, not proof | HTTPS missing |
| 15 | Medium — worth noting | URL length, urgency language |
| 20 | Medium-high — suspicious pattern | IP address, subdomains, special chars, threats |
| 25 | High — strong phishing signal | Credential request, financial request |

---

## Important Caveat

These weights work well for OBVIOUS phishing attempts but can produce:
- **False positives** — A legit long URL with "login" in it gets flagged.
- **False negatives** — A phishing email with perfect grammar and no keywords
  slips through.

This is expected for a heuristic system. See [08_LIMITATIONS_AND_FUTURE.md](08_LIMITATIONS_AND_FUTURE.md).
