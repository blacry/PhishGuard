"""
main.py — Entry point for PhishGuard CLI application.

This is the file you run to start PhishGuard. It shows a menu,
takes the user's choice, and calls the right scanner or utility.

Think of it as the "receptionist" of the app: it greets the user,
asks what they need, and routes them to the correct department.

Python concepts used:
    - while loop (to keep the menu running until the user quits)
    - if/elif/else (to handle menu choices)
    - input() for reading user input
    - try/except for preventing crashes on bad input
    - functions for organizing code into reusable blocks
"""


from utils.validators import is_valid_url, is_valid_message
from scanners.url_scanner import scan_url
from scanners.message_scanner import scan_message
from engine.risk_engine import calculate_risk_score, classify_threat
from engine.recommendation_engine import generate_explanation, generate_recommendations
from utils.helpers import save_scan, load_scan_history, generate_statistics


def display_banner():
    """
    Print the PhishGuard welcome banner.

    Takes:   Nothing.
    Returns: Nothing (just prints to screen).
    """
    print("=" * 55)
    print("       [*] PhishGuard - Phishing Detector v1.0")
    print("       Analyze URLs and messages for phishing risk")
    print("=" * 55)
    print()


def display_menu():
    """
    Print the main menu options.

    Takes:   Nothing.
    Returns: Nothing (just prints to screen).
    """
    print("What would you like to do?")
    print("-" * 30)
    print("  1. Scan a URL")
    print("  2. Scan a message")
    print("  3. View scan history")
    print("  4. View statistics")
    print("  5. Exit")
    print("-" * 30)


def get_user_choice():
    """
    Ask the user to pick a menu option and return it safely.

    Takes:   Nothing (reads from keyboard via input()).
    Returns: An integer (1-5) if the input is valid, or -1 on error.
    """
    try:
        choice = int(input("Enter your choice (1-5): ").strip())
        return choice
    except ValueError:
        return -1


def handle_url_scan():
    """
    Handle option 1: Scan a URL for phishing indicators.
    Pipeline: Input -> Validate -> Scan -> Score -> Explain -> Recommend -> Save.
    """
    print("\n" + "=" * 55)
    print("                [ URL SCANNER ]")
    print("=" * 55)
    raw_url = input("\nEnter the URL to analyze: ").strip()

    if not is_valid_url(raw_url):
        print("\n[!] Error: Invalid URL provided.")
        print("    Please enter a valid web address (e.g., http://example.com).\n")
        return

    print("\n[*] Analyzing URL structure (static analysis)...")
    results = scan_url(raw_url)
    score = calculate_risk_score(results)
    threat_level = classify_threat(score)
    explanation = generate_explanation(results)
    recommendations = generate_recommendations(threat_level, results)

    # Print structured report
    print("\n" + "-" * 55)
    print(f" SCAN REPORT: {raw_url}")
    print("-" * 55)
    print(f" Risk Score   : {score} / 100")
    print(f" Threat Level : [{threat_level}]")
    print("-" * 55)
    print("\nINDICATOR BREAKDOWN:")
    print(explanation)
    print("\nSAFETY RECOMMENDATIONS:")
    for i, rec in enumerate(recommendations, 1):
        print(f"  {i}. {rec}")
    print("-" * 55)

    # Save to history log
    triggered = [r["indicator"] for r in results if r.get("triggered")]
    indicators_str = "; ".join(triggered) if triggered else "none"
    saved = save_scan({
        "input_type": "url",
        "input": raw_url,
        "risk_score": score,
        "threat_level": threat_level,
        "indicators": indicators_str
    })
    if saved:
        print("[*] Scan successfully logged to data/scan_history.csv\n")
    else:
        print("[!] Note: Could not save scan to history log.\n")


def handle_message_scan():
    """
    Handle option 2: Scan a text message for phishing indicators.
    Pipeline: Input -> Validate -> Scan text + Scan embedded URLs -> Score -> Explain -> Recommend -> Save.
    """
    print("\n" + "=" * 55)
    print("              [ MESSAGE SCANNER ]")
    print("=" * 55)
    print("Paste or type the suspicious message below:")
    raw_msg = input("> ").strip()

    if not is_valid_message(raw_msg):
        print("\n[!] Error: Message is too short or empty.")
        print("    Please provide a complete message with at least a few words.\n")
        return

    print("\n[*] Analyzing message text for phishing indicators...")
    msg_result = scan_message(raw_msg)
    all_indicators = list(msg_result["message_indicators"])

    # If URLs are found inside the message, also analyze their structure
    extracted_urls = msg_result.get("extracted_urls", [])
    if extracted_urls:
        print(f"[*] Found {len(extracted_urls)} embedded link(s). Analyzing URL structure...")
        for u in extracted_urls:
            url_indicators = scan_url(u)
            all_indicators.extend(url_indicators)

    score = calculate_risk_score(all_indicators)
    threat_level = classify_threat(score)
    explanation = generate_explanation(all_indicators)
    recommendations = generate_recommendations(threat_level, all_indicators)

    # Print structured report
    print("\n" + "-" * 55)
    print(" SCAN REPORT: Message Content")
    print("-" * 55)
    print(f" Risk Score   : {score} / 100")
    print(f" Threat Level : [{threat_level}]")
    if extracted_urls:
        print(f" Embedded URLs: {', '.join(extracted_urls)}")
    print("-" * 55)
    print("\nINDICATOR BREAKDOWN:")
    print(explanation)
    print("\nSAFETY RECOMMENDATIONS:")
    for i, rec in enumerate(recommendations, 1):
        print(f"  {i}. {rec}")
    print("-" * 55)

    # Save to history log
    triggered = [r["indicator"] for r in all_indicators if r.get("triggered")]
    indicators_str = "; ".join(triggered) if triggered else "none"
    saved = save_scan({
        "input_type": "message",
        "input": raw_msg,
        "risk_score": score,
        "threat_level": threat_level,
        "indicators": indicators_str
    })
    if saved:
        print("[*] Scan successfully logged to data/scan_history.csv\n")
    else:
        print("[!] Note: Could not save scan to history log.\n")


def handle_view_history():
    """
    Handle option 3: Show past scan results from data/scan_history.csv.
    """
    print("\n" + "=" * 55)
    print("               [ SCAN HISTORY ]")
    print("=" * 55)
    records = load_scan_history()
    if not records:
        print("\n[*] No scan history found. Scans will appear here after you analyze URLs or messages.\n")
        return

    recent = records[-10:]
    print(f"\nShowing {len(recent)} most recent scan(s):\n")
    print(f"{'#':<3} {'Timestamp':<20} {'Type':<8} {'Score':<6} {'Threat':<9} {'Input Preview'}")
    print("-" * 75)
    for idx, r in enumerate(recent, 1):
        t_stamp = r.get("timestamp", "N/A")[:19]
        itype = r.get("input_type", "N/A")
        score = r.get("risk_score", "0")
        level = r.get("threat_level", "LOW")
        inp = r.get("input", "")
        if len(inp) > 28:
            inp = inp[:25] + "..."
        print(f"{idx:<3} {t_stamp:<20} {itype:<8} {score:<6} {level:<9} {inp}")
    print("-" * 75 + "\n")


def handle_statistics():
    """
    Handle option 4: Show summary statistics of all scans with an ASCII chart.
    """
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
    print("\n" + "=" * 55 + "\n")



def main():
    """
    The main function — runs the CLI menu loop.

    Takes:   Nothing.
    Returns: Nothing.
    Why:     This is the "engine" of the app. It:
             1. Shows the banner once.
             2. Loops forever, showing the menu each time.
             3. Reads the user's choice.
             4. Calls the right handler function.
             5. Stops looping only when the user picks Exit (5).

    The while True loop keeps the program alive until the user
    explicitly chooses to quit. This is a common CLI pattern.
    """
    display_banner()

    # This loop runs forever until the user picks option 5 (Exit).
    # "while True" means "keep going"; we use "break" to stop.
    while True:
        display_menu()
        choice = get_user_choice()

        if choice == 1:
            handle_url_scan()
        elif choice == 2:
            handle_message_scan()
        elif choice == 3:
            handle_view_history()
        elif choice == 4:
            handle_statistics()
        elif choice == 5:
            print("\nThank you for using PhishGuard! Stay safe online. [*]")
            break  # Exit the while loop → program ends
        else:
            # This catches invalid numbers AND the -1 from bad input
            print("\n[!] Invalid choice. Please enter a number from 1 to 5.\n")


# --- This block runs only when you execute "python main.py" directly ---
# If another file imports main.py, this block is skipped.
# It's a Python convention that protects your code from running
# accidentally during imports.
if __name__ == "__main__":
    main()
