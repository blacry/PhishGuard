"""Turn detected indicators into practical next steps."""


def get_recommendations(findings, category="content"):
    keys = {item.get("key", "") for item in findings or []}
    advice = []
    if any("brand_impersonation" in key for key in keys):
        advice.append("Open the service through its official app or a bookmarked address instead of this link.")
    if "sensitive_request" in keys or "otp_request" in keys:
        advice.append("Never share a password, PIN, or one-time code through a message or link.")
    if "shortened_url" in keys or "ip_address" in keys or "misleading_at" in keys:
        advice.append("Do not open the link. Verify the destination through a separate trusted channel.")
    if "urgent_language" in keys or "fake_reward" in keys or "scam_pattern" in keys:
        advice.append("Pause before responding to urgent threats, prizes, or payment requests; contact the organization directly.")
    if "http" in keys:
        advice.append("Avoid entering information on this unencrypted page.")
    if not advice:
        advice.append("No strong warning was found by these local checks. Stay cautious and verify unexpected requests independently.")
    if category == "email":
        advice.append("Sender identity and email authentication were not verified from body text alone.")
    advice.append("Treat this score as a heuristic assessment, not a probability or guarantee.")
    return list(dict.fromkeys(advice))
