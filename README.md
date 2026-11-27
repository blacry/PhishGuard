# PhishGuard

**Detect. Analyse. Protect.**

PhishGuard is a beginner-friendly Python application for checking potentially suspicious URLs, emails, SMS messages, chat messages, and QR codes. It uses transparent rules and explains each warning so a user can decide how to verify a message safely.

## Problem statement

Phishing messages often use urgency, fake rewards, lookalike domains, and links that hide their destination. People need a simple way to inspect these clues before clicking or sharing information.

## Objectives

- Analyse common URL and message warning signs without opening links.
- Explain every detected indicator and provide practical next steps.
- Produce a capped risk score using understandable weighted rules.
- Keep a local scan history without retaining full email or message contents.
- Offer optional reputation lookup, PDF reports, and QR decoding.

## Features

- URL analysis: protocol, hostname, raw IPs, domain ending, subdomains, URL length, shorteners, keywords, and unusual URL structures.
- Email and message analysis with URL extraction and checks for urgency, credential requests, rewards, payments, and common scam patterns.
- Possible brand lookalike warnings using a small local list and string similarity.
- Optional VirusTotal lookup of an existing URL report. The app does not submit new URLs or email contents.
- QR code decoding for PNG and JPG uploads (5 MB maximum); decoded URLs are analysed without being opened.
- Downloadable PDF reports, local JSON scan history, dashboard statistics, and security awareness guidance.

All scores are heuristic estimates, not probabilities or guarantees. HTTPS does not prove legitimacy, and the absence of warnings does not prove safety.

## Technology stack

Python, Streamlit, Requests, urllib.parse, regular expressions, ipaddress, JSON, Pandas, OpenCV, Pillow, difflib, and ReportLab.

## Folder structure

```text
PhishGuard/
├── app.py
├── detectors/       # URL, email, message, and brand checks
├── core/            # scoring, recommendations, PDF reports
├── services/        # VirusTotal and QR code helpers
├── database/        # local JSON history
├── tests/           # unittest checks
├── requirements.txt
└── README.md
```

## Installation

Python 3.10 or newer is recommended.

```bash
python -m venv .venv
```

Activate the environment:

```powershell
# Windows PowerShell
.venv\Scripts\Activate.ps1
```

```bash
# macOS / Linux
source .venv/bin/activate
```

Install packages:

```bash
python -m pip install -r requirements.txt
```

## Run the application

```bash
streamlit run app.py
```

Streamlit prints a local address to open in a browser. The basic scanners work without an API key or internet connection.

## Optional VirusTotal setup

Get a personal key from your VirusTotal account settings at [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey). Then use either a Streamlit secrets file or an environment variable. A key is never required for local analysis.

For a Streamlit secrets file, create `.streamlit/secrets.toml` in the project root with:

```toml
VIRUSTOTAL_API_KEY = "your-api-key"
```

Alternatively, set `VIRUSTOTAL_API_KEY` in your environment before launching Streamlit. For PowerShell:

```powershell
$env:VIRUSTOTAL_API_KEY = "your-api-key"
streamlit run app.py
```

The URL scanner only looks up a URL in VirusTotal's existing database after the user checks the lookup option. It does not submit URLs, page contents, or email text. API keys are never written to scan history or reports. VirusTotal requires an account and uses the `x-apikey` request header; see its [authentication guide](https://docs.virustotal.com/reference/authentication).

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Screenshots

Add screenshots of the dashboard and scanner reports here after running the application locally.

## Limitations

- Rule-based checks can miss new attacks and can produce false positives.
- Brand domain parsing uses a small local list and a simple public-suffix approximation.
- VirusTotal results depend on an API key, network access, and the URL's existing report.
- QR handling decodes one QR code per image; multiple QR codes may not be supported by the installed OpenCV build.
- Email sender format is not sender authentication. Header and SPF/DKIM checks are not performed.
- Local history is stored on the device and is not encrypted.

## Future scope

- Add a curated, maintainable public suffix list for more precise domain parsing.
- Improve accessibility and add report comparisons over time.
- Add additional local rules based on carefully reviewed examples.
- Add explicit support for multiple QR codes when the installed decoder allows it.
