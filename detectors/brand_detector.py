"""Basic brand lookalike detection using a small local brand list."""

from difflib import SequenceMatcher

BRANDS = {
    "google": {"google.com", "google.co.in"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.in", "amazon.co.uk"},
    "paypal": {"paypal.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi"},
    "hdfc bank": {"hdfcbank.com"},
    "icici bank": {"icicibank.com"},
    "apple": {"apple.com", "icloud.com"},
    "instagram": {"instagram.com"},
    "facebook": {"facebook.com", "fb.com"},
}


def registered_domain(host):
    """Approximate the registered domain without requiring a public suffix list."""
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and labels[-2] in {"co", "com", "org", "net", "gov", "ac"} and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def detect_brand_impersonation(host):
    domain = registered_domain(host)
    # Only compare against the registrable portion; official subdomains are allowed.
    for brand, official_domains in BRANDS.items():
        normalized_official = {registered_domain(item) for item in official_domains}
        if domain in normalized_official:
            return None
        brand_token = brand.replace(" ", "")
        domain_token = domain.split(".")[0].replace("-", "")
        similarity = SequenceMatcher(None, brand_token, domain_token).ratio()
        has_brand = brand_token in domain_token
        if (similarity >= 0.72 and domain_token != brand_token) or has_brand:
            display = brand.title()
            return {
                "key": "brand_impersonation_" + brand_token,
                "indicator": "Possible " + display + " impersonation",
                "points": 20,
                "severity": "High",
                "explanation": "The registered domain '" + domain + "' resembles or embeds the " + display + " brand, but is not in its known official domain list. Similarity is only a warning, not proof of fraud.",
                "brand": display,
            }
    return None
