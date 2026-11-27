"""Shared rule checks for email bodies and other messages."""

import re

from detectors.url_detector import analyze_url

URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")
URGENT_TERMS = ("immediately", "within 24 hours", "account suspended", "account blocked", "act now", "final warning", "urgent", "expires today", "will be closed")
SENSITIVE_TERMS = ("password", "one-time password", "otp", "pin", "cvv", "bank details", "card number", "verification code")
REWARD_TERMS = ("you won", "winner", "lottery", "claim your prize", "free reward", "selected for a prize")


def extract_urls(text):
    found = []
    for match in URL_PATTERN.findall(text or ""):
        cleaned = match.rstrip('.,;:!?)]}"}')
        if cleaned and cleaned not in found:
            found.append(cleaned)
    return found


def analyze_text(text, category="message", sender=""):
    text = (text or "").strip()
    findings = []

    def add(key, name, points, severity, explanation):
        findings.append({"key": key, "indicator": name, "points": points, "severity": severity, "explanation": explanation})

    lowered = text.lower()
    if any(term in lowered for term in URGENT_TERMS):
        add("urgent_language", "Urgent or threatening language", 10, "Medium", "The text pressures the reader to act quickly or threatens an account consequence.")
    if any(term in lowered for term in SENSITIVE_TERMS):
        add("sensitive_request", "Sensitive information mentioned", 20, "High", "The message mentions credentials or financial verification information. Never share passwords, PINs, or OTPs in response to a message.")
    if any(term in lowered for term in REWARD_TERMS):
        add("fake_reward", "Possible fake reward or lottery", 15, "Medium", "Unexpected prizes and lottery claims are a common way to draw people into sharing information or paying fees.")
    patterns = [
        ("scam_pattern", "Possible account or delivery scam", ("kyc update", "verify kyc", "delivery failed", "package held", "bank account suspended", "payment failed"), "The text resembles a common bank, KYC, delivery, or payment notice used in phishing messages."),
        ("payment_request", "Urgent payment request", ("pay now", "send payment", "transfer money", "pay a fee"), "The message asks for payment under pressure. Verify the request using an official channel."),
        ("job_scam", "Possible fake job offer", ("work from home", "job offer", "registration fee", "earn daily"), "Unsolicited job offers that request fees or promise unusually easy earnings deserve careful verification."),
    ]
    for key, name, terms, explanation in patterns:
        if any(term in lowered for term in terms):
            add(key, name, 10, "Medium", explanation)
    urls = extract_urls(text)
    url_results = [analyze_url(url) for url in urls]
    for index, result in enumerate(url_results):
        for item in result.get("findings", []):
            # Shared indicators such as a suspicious URL keyword count once across an email.
            findings.append(dict(item))
    if sender.strip() and not re.search(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", sender.strip()):
        add("suspicious_sender", "Unusual sender address", 10, "Medium", "The supplied sender address does not match a basic email-address format. This check does not authenticate the sender.")
    return {"valid": bool(text), "category": category, "findings": findings, "urls": urls, "url_results": url_results, "sender": sender.strip(), "error": None if text else "Enter the message or email content to analyse."}
