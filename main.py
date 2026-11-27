"""Interactive command-line entry point for PhishGuard."""

from engine.recommendation_engine import (
    generate_explanation,
    generate_recommendations,
)
from engine.risk_engine import calculate_risk_score, classify_with_reputation
from scanners.message_scanner import scan_message
from scanners.reputation import (
    lookup_url_reputation,
    summarize_reputation_results,
)
from scanners.url_scanner import scan_url
from utils.charts import save_threat_distribution_chart
from utils.helpers import (
    delete_scan_history,
    generate_statistics,
    load_scan_history,
    save_scan,
)
from utils.validators import is_valid_message, is_valid_url


def display_banner():
    print("=" * 55)
    print("       [*] PhishGuard - Phishing Detector v1.0")
    print("       Analyze URLs and messages for phishing risk")
    print("=" * 55)
    print()


def display_menu():
    print("What would you like to do?")
    print("-" * 30)
    print("  1. Scan a URL")
    print("  2. Scan a message")
    print("  3. View scan history")
    print("  4. View statistics")
    print("  5. Delete scan history")
    print("  6. Exit")
    print("-" * 30)


def _read_prompt(prompt):
    """Read one prompt without letting EOF or Ctrl+C produce a traceback."""
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        return None


def get_user_choice():
    """
    Ask the user to pick a menu option and return it safely.

    Takes:   Nothing (reads from keyboard via input()).
    Returns: An integer (1-6), -1 for invalid input, or None if interrupted.
    """
    choice_text = _read_prompt("Enter your choice (1-6): ")
    if choice_text is None:
        return None
    try:
        return int(choice_text.strip())
    except ValueError:
        return -1


def handle_url_scan():
    """Validate, analyze, explain, and save one URL scan."""
    print("\n" + "=" * 55)
    print("                [ URL SCANNER ]")
    print("=" * 55)
    raw_url = _read_prompt("\nEnter the URL to analyze: ")
    if raw_url is None:
        print("\n[*] URL scan canceled.\n")
        return
    raw_url = raw_url.strip()

    if not is_valid_url(raw_url):
        print("\n[!] Error: Invalid URL provided.")
        print("    Please enter a valid web address (e.g., http://example.com).\n")
        return

    print("\n[*] Analyzing URL structure (static analysis)...")
    results = scan_url(raw_url)
    score = calculate_risk_score(results)
    reputation = lookup_url_reputation(raw_url)
    reputation_results = [reputation]
    threat_level = classify_with_reputation(score, reputation_results)
    explanation = generate_explanation(results)
    recommendations = generate_recommendations(threat_level, results)

    print("\n" + "-" * 55)
    print(f" SCAN REPORT: {raw_url}")
    print("-" * 55)
    print(f" Risk Score   : {score} / 100")
    print(f" Threat Level : [{threat_level}]")
    print(f" Reputation   : [{reputation['status'].upper()}] ({reputation['source']})")
    print(f"   {reputation['detail']}")
    if reputation["status"] == "known_malicious":
        print(
            "   Reputation verdict raises the threat level; "
            "it does not change the heuristic score."
        )
    print("-" * 55)
    print("\nINDICATOR BREAKDOWN:")
    print(explanation)
    print("\nSAFETY RECOMMENDATIONS:")
    for i, rec in enumerate(recommendations, 1):
        print(f"  {i}. {rec}")
    print("-" * 55)

    triggered = [r["indicator"] for r in results if r.get("triggered")]
    indicators_str = "; ".join(triggered) if triggered else "none"
    saved = save_scan({
        "input_type": "url",
        "input": raw_url,
        "risk_score": score,
        "threat_level": threat_level,
        "indicators": indicators_str,
        "reputation_status": reputation["status"],
        "reputation_source": reputation["source"],
    })
    if saved:
        print("[*] Scan metadata saved to data/scan_history.sqlite3.")
        print("    Submitted content is not stored unless encryption is configured.\n")
    else:
        print("[!] Note: Could not save scan to history log.\n")


def handle_message_scan():
    """Analyze a message and its embedded URLs, then save the result."""
    print("\n" + "=" * 55)
    print("              [ MESSAGE SCANNER ]")
    print("=" * 55)
    print("Paste or type the suspicious message below:")
    raw_msg = _read_prompt("> ")
    if raw_msg is None:
        print("\n[*] Message scan canceled.\n")
        return
    raw_msg = raw_msg.strip()

    if not is_valid_message(raw_msg):
        print("\n[!] Error: Message is too short or empty.")
        print("    Please provide a complete message with at least a few words.\n")
        return

    print("\n[*] Analyzing message text for phishing indicators...")
    msg_result = scan_message(raw_msg)
    all_indicators = list(msg_result["message_indicators"])
    reputation_results = []

    extracted_urls = msg_result.get("extracted_urls", [])
    if extracted_urls:
        print(f"[*] Found {len(extracted_urls)} embedded link(s). Analyzing URL structure...")
        for u in extracted_urls:
            url_indicators = scan_url(u)
            all_indicators.extend(url_indicators)
            reputation_results.append(lookup_url_reputation(u))

    score = calculate_risk_score(all_indicators)
    threat_level = classify_with_reputation(score, reputation_results)
    reputation_status, reputation_source = summarize_reputation_results(reputation_results)
    explanation = generate_explanation(all_indicators)
    recommendations = generate_recommendations(threat_level, all_indicators)

    print("\n" + "-" * 55)
    print(" SCAN REPORT: Message Content")
    print("-" * 55)
    print(f" Risk Score   : {score} / 100")
    print(f" Threat Level : [{threat_level}]")
    if extracted_urls:
        print(f" Embedded URLs: {', '.join(extracted_urls)}")
    if reputation_results:
        print("\nREPUTATION CHECKS (separate from heuristic score):")
        for index, result in enumerate(reputation_results, 1):
            print(
                f"  {index}. [{result['status'].upper()}] "
                f"{result['source']}: {result['detail']}"
            )
    else:
        print(f" Reputation   : [{reputation_status.upper()}] (no embedded URLs to check)")
    print("-" * 55)
    print("\nINDICATOR BREAKDOWN:")
    print(explanation)
    print("\nSAFETY RECOMMENDATIONS:")
    for i, rec in enumerate(recommendations, 1):
        print(f"  {i}. {rec}")
    print("-" * 55)

    triggered = [r["indicator"] for r in all_indicators if r.get("triggered")]
    indicators_str = "; ".join(triggered) if triggered else "none"
    saved = save_scan({
        "input_type": "message",
        "input": raw_msg,
        "risk_score": score,
        "threat_level": threat_level,
        "indicators": indicators_str,
        "reputation_status": reputation_status,
        "reputation_source": reputation_source,
    })
    if saved:
        print("[*] Scan metadata saved to data/scan_history.sqlite3.")
        print("    Submitted content is not stored unless encryption is configured.\n")
    else:
        print("[!] Note: Could not save scan to history log.\n")


def handle_view_history():
    """Display recent scan records from the local database."""
    print("\n" + "=" * 55)
    print("               [ SCAN HISTORY ]")
    print("=" * 55)
    records = load_scan_history()
    if not records:
        print(
            "\n[*] No scan history found. Scans will appear here after you "
            "analyze URLs or messages.\n"
        )
        return

    recent = records[-10:]
    print(f"\nShowing {len(recent)} most recent scan(s):\n")
    print(
        f"{'#':<3} {'Timestamp':<20} {'Type':<8} {'Score':<6} "
        f"{'Threat':<9} {'Reputation':<18} {'Input (redacted by default)'}"
    )
    print("-" * 100)
    for idx, r in enumerate(recent, 1):
        t_stamp = r.get("timestamp", "N/A")[:19]
        itype = r.get("input_type", "N/A")
        score = r.get("risk_score", "0")
        level = r.get("threat_level", "LOW")
        reputation = r.get("reputation_status", "not_checked")
        inp = r.get("input", "")
        if len(inp) > 28:
            inp = inp[:25] + "..."
        print(f"{idx:<3} {t_stamp:<20} {itype:<8} {score:<6} {level:<9} {reputation:<18} {inp}")
    print("-" * 100 + "\n")


def handle_delete_history():
    """Ask for confirmation before deleting all saved scan records."""
    confirmation = _read_prompt(
        "\nDelete all saved scan records? This cannot be undone. (y/n): "
    )
    if confirmation is None:
        print("[*] Scan history was not deleted.\n")
        return
    confirmation = confirmation.strip().lower()
    if confirmation not in ("y", "yes"):
        print("[*] Scan history was not deleted.\n")
        return

    deleted = delete_scan_history()
    if deleted is None:
        print("[!] Could not delete scan history.\n")
    else:
        print(f"[*] Deleted {deleted} scan record(s). Audit metadata was retained.\n")


def handle_statistics():
    """Display scan statistics and optionally export a chart."""
    print("\n" + "=" * 55)
    print("              [ SCAN STATISTICS ]")
    print("=" * 55)
    stats = generate_statistics()
    if not stats:
        print("\n[*] No scan data available yet to compute statistics.\n")
        return

    print(f"\nTotal Scans Analyzed : {stats['total_scans']}")
    print(f"  - URL Scans         : {stats['url_scans']}")
    print(f"  - Message Scans     : {stats['message_scans']}")
    print(f"Average Risk Score    : {stats['average_risk_score']} / 100")
    print("\nThreat Level Distribution:")
    dist = stats["threat_distribution"]
    total = stats["total_scans"]
    for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        count = dist.get(level, 0)
        pct = (count / total * 100) if total > 0 else 0
        bars = "#" * int(pct // 5)
        print(f"  {level:<8}: {count:>3} ({pct:>5.1f}%) | {bars}")
    print("-" * 55)

    export_choice = _read_prompt(
        "\nWould you like to export a visual chart image? (y/n): "
    )
    if export_choice is None:
        print("[*] Chart export canceled.\n")
    elif export_choice.strip().lower() in ("y", "yes"):
        print("[*] Generating visual analytics chart using matplotlib...")
        chart_file = save_threat_distribution_chart()
        if chart_file:
            print(f"[*] Visual chart saved to: {chart_file}\n")
        else:
            print("[!] Could not generate chart: no scan history found.\n")
    else:
        print()




def main():
    display_banner()

    while True:
        display_menu()
        choice = get_user_choice()

        if choice is None:
            print("\n[*] Input ended or interrupted. Exiting PhishGuard.\n")
            break
        if choice == 1:
            handle_url_scan()
        elif choice == 2:
            handle_message_scan()
        elif choice == 3:
            handle_view_history()
        elif choice == 4:
            handle_statistics()
        elif choice == 5:
            handle_delete_history()
        elif choice == 6:
            print("\nThank you for using PhishGuard! Stay safe online. [*]")
            break
        else:
            print("\n[!] Invalid choice. Please enter a number from 1 to 6.\n")


if __name__ == "__main__":
    main()
