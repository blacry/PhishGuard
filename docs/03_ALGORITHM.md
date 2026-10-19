# 03 — Algorithm

## What is an Algorithm?

An algorithm is a step-by-step recipe for solving a problem. Just like a
cooking recipe says "add flour, then eggs, then mix", our algorithm says
"check HTTPS, then check IP, then add up scores."

---

## PhishGuard Algorithm in Plain English

### For URL Scanning:

1. **Read** the URL from the user.
2. **Validate** — Is it actually a URL? If not, show an error and go back.
3. **Check HTTPS** — Does it start with `https://`? If not, mark as triggered.
4. **Check IP address** — Does the domain look like `192.168.x.x`? If yes, mark as triggered.
5. **Check URL length** — Is it longer than 75 characters? If yes, mark as triggered.
6. **Check subdomains** — Does it have 3 or more subdomains? If yes, mark as triggered.
7. **Check suspicious keywords** — Does it contain words like "login", "verify"? If yes, mark as triggered and list which keywords matched.
8. **Check special characters** — Does it contain `@` or unusual `//`? If yes, mark as triggered.
9. **Collect** all results into a list.
10. **Calculate score** — For each triggered indicator, add its weight. Cap at 100.
11. **Classify** — Map the score to LOW / MEDIUM / HIGH / CRITICAL.
12. **Explain** — Build a text explaining what triggered and why.
13. **Recommend** — Pick safety tips based on the threat level.
14. **Display** the results to the user.
15. **Save** the scan to `scan_history.csv`.

### For Message Scanning:

1. **Read** the message from the user.
2. **Validate** — Is it long enough to analyze? If not, show an error.
3. **Extract URLs** — Find any URLs embedded in the message.
4. **Check urgency** — Does it use panic-inducing language? Mark if yes.
5. **Check threats** — Does it threaten the reader? Mark if yes.
6. **Check credential requests** — Does it ask for passwords/personal info? Mark if yes.
7. **Check financial requests** — Does it ask for money/bank details? Mark if yes.
8. **If URLs were found** — Run the URL scanning algorithm on each one.
9. **Combine** all message indicators + URL indicators.
10. **Calculate score**, **classify**, **explain**, **recommend**, **display**, **save** — same as URL scanning steps 10–15.

---

## Pseudocode

```
FUNCTION scan_url(url):
    results = empty list

    IF url does NOT start with "https://":
        ADD {indicator: "https", triggered: True, detail: "No HTTPS"} to results
    ELSE:
        ADD {indicator: "https", triggered: False, detail: "HTTPS present"} to results

    IF url contains an IP address pattern (like 192.168.x.x):
        ADD {indicator: "ip_address", triggered: True, ...} to results

    IF length of url > 75:
        ADD {indicator: "url_length", triggered: True, ...} to results

    count subdomains by counting dots in the domain part
    IF subdomain_count >= 3:
        ADD {indicator: "subdomains", triggered: True, ...} to results

    FOR each keyword in suspicious_keywords_list:
        IF keyword is found in url:
            ADD keyword to matched_keywords
    IF matched_keywords is not empty:
        ADD {indicator: "suspicious_keywords", triggered: True, ...} to results

    IF url contains "@" or unusual "//":
        ADD {indicator: "special_chars", triggered: True, ...} to results

    RETURN results
END FUNCTION


FUNCTION calculate_risk_score(indicator_results):
    total = 0
    FOR each result in indicator_results:
        IF result.triggered is True:
            weight = INDICATOR_WEIGHTS[result.indicator]
            total = total + weight
    capped_score = MINIMUM(total, 100)
    RETURN capped_score
END FUNCTION


FUNCTION classify_threat(score):
    IF score <= 24:
        RETURN "LOW"
    ELSE IF score <= 49:
        RETURN "MEDIUM"
    ELSE IF score <= 74:
        RETURN "HIGH"
    ELSE:
        RETURN "CRITICAL"
END FUNCTION
```

---

## Why This Algorithm Works

- **Multiple indicators** — No single check is conclusive. A URL with just
  HTTP isn't necessarily phishing. But HTTP + IP address + "login" keyword?
  That's very suspicious. Multiple weak signals combine into strong signals.

- **Weighted scoring** — Not all indicators are equally important. Asking for
  credentials (weight 20) is more suspicious than a long URL (weight 10).
  Weights let us express this.

- **Capped at 100** — So the score stays on a simple, intuitive scale.

- **Classification** — Turns numbers into words. "72" is hard to interpret.
  "HIGH" is immediately clear.

---

## Note on the Scoring Approach

Our weights are **heuristics** — educated guesses based on how phishing
typically works. They are NOT trained from data or mathematically proven.
Different security experts might choose different weights. That's okay
for a v1 educational project. See [04_INDICATORS_AND_WEIGHTS.md](04_INDICATORS_AND_WEIGHTS.md)
for the full weight table and rationale.
