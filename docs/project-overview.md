# Project overview

## Name and purpose

**PhishGuard URL Check — Detect. Analyse. Protect.** is a small Python application for checking whether a submitted URL appears in a local URLhaus malware URL database.

## Problem

People receive links that may lead to malware. A URL lookup service can compare a link with known reports, but the result depends on the database having seen that exact link or its host. This project demonstrates a local, explainable lookup using a supplied CSV dump.

## Objectives

- Load a malware URL dataset from a ZIP file.
- Check a URL without visiting it.
- Display an exact-match malware verdict or a related-host warning.
- Clearly report URLs that are absent from the dataset as “not listed.”
- Keep the application small enough to understand and explain in a first-year Python viva.

## Input and output

**Input:** one HTTP or HTTPS URL, optionally without a scheme.

**Output:** one of three statuses:

- **MALWARE:** the normalized full URL exactly matches a database record.
- **POTENTIALLY MALICIOUS:** the exact URL is absent, but the hostname has listed records.
- **NOT LISTED:** neither the full URL nor hostname appears in the local snapshot.

The app also shows the matched record's threat type, database status, date, and record ID when relevant.

## Technology

- Python: ZIP/CSV parsing and URL matching.
- Streamlit: the one-page browser interface.
- Python standard library: `zipfile`, `csv`, `urllib.parse`, and `unittest`.

The only direct package dependency is Streamlit. No machine learning, API keys, external lookups, or network requests are used.

## Limitations

The dataset is a snapshot and may become outdated. An unlisted URL might be safe, but it may also be new or missing from the dataset. A hostname warning does not mean every path on that host is malicious. URL normalization is intentionally simple and exact-match results depend on the feed's formatting.
