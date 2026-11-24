"""Command-line entry point for PhishGuard."""

from scanner import get_explanation, get_recommendations, scan_message, scan_url
from scanners.message_scanner import extract_urls
from storage import add_scan, get_history, get_stats


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
    print("  5. Exit")
    print("-" * 30)


def get_user_choice():
    try:
        return int(input("Enter your choice (1-5): ").strip())
    except ValueError:
        return -1


def _show_result(title, scan_input, scan_type, result, embedded_urls=None):
    print("\n" + "-" * 55)
    print(f" SCAN REPORT: {title}")
    print("-" * 55)
    print(f" Risk Score   : {result['score']} / 100")
    print(f" Threat Level : [{result['level']}]")
    if embedded_urls:
        print(f" Embedded URLs: {', '.join(embedded_urls)}")
    print("-" * 55)
    print("\nINDICATOR BREAKDOWN:")
    print(get_explanation(result))
    print("\nSAFETY RECOMMENDATIONS:")
    for index, recommendation in enumerate(get_recommendations(result), 1):
        print(f"  {index}. {recommendation}")
    print("-" * 55)

    try:
        add_scan(scan_type, scan_input, result["score"], result["level"])
    except (OSError, ValueError) as error:
        print(f"[!] Note: Could not save scan to history.json: {error}\n")
    else:
        print("[*] Scan successfully logged to history.json\n")


def handle_url_scan():
    print("\n" + "=" * 55)
    print("                [ URL SCANNER ]")
    print("=" * 55)
    raw_url = input("\nEnter the URL to analyze: ").strip()
    try:
        result = scan_url(raw_url)
    except ValueError:
        print("\n[!] Error: Invalid URL provided.")
        print("    Please enter a valid web address (e.g., http://example.com).\n")
        return

    print("\n[*] Analyzing URL structure (static analysis)...")
    _show_result(raw_url, raw_url, "URL", result)


def handle_message_scan():
    print("\n" + "=" * 55)
    print("              [ MESSAGE SCANNER ]")
    print("=" * 55)
    print("Paste or type the suspicious message below:")
    raw_message = input("> ").strip()
    try:
        result = scan_message(raw_message)
    except ValueError:
        print("\n[!] Error: Message is too short or empty.")
        print("    Please provide a complete message with at least a few words.\n")
        return

    print("\n[*] Analyzing message text for phishing indicators...")
    embedded_urls = extract_urls(raw_message)
    if embedded_urls:
        print(f"[*] Found {len(embedded_urls)} embedded link(s). Analyzing URL structure...")
    _show_result("Message Content", raw_message, "Message", result, embedded_urls)


def handle_view_history():
    print("\n" + "=" * 55)
    print("               [ SCAN HISTORY ]")
    print("=" * 55)
    try:
        records = get_history()
    except (OSError, ValueError) as error:
        print(f"\n[!] Could not read scan history: {error}\n")
        return
    if not records:
        print("\n[*] No scan history found. Scans will appear here after you analyze URLs or messages.\n")
        return

    recent = records[-10:]
    print(f"\nShowing {len(recent)} most recent scan(s):\n")
    print(f"{'#':<3} {'Timestamp':<20} {'Type':<8} {'Score':<6} {'Threat':<9} {'Input Preview'}")
    print("-" * 75)
    for index, record in enumerate(recent, 1):
        timestamp = record.get("timestamp", "N/A")[:19]
        scan_type = record.get("type", "N/A")
        score = record.get("score", 0)
        level = record.get("level", "LOW")
        preview = record.get("input", "")
        if len(preview) > 28:
            preview = preview[:25] + "..."
        print(f"{index:<3} {timestamp:<20} {scan_type:<8} {score:<6} {level:<9} {preview}")
    print("-" * 75 + "\n")


def _save_threat_distribution_chart(counts):
    import os

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    values = [counts[level] for level in levels]
    figure, axis = plt.subplots(figsize=(8, 5))
    bars = axis.bar(levels, values, color=["#2ecc71", "#f39c12", "#e67e22", "#e74c3c"])
    axis.set_title("PhishGuard Threat Level Distribution")
    axis.set_ylabel("Number of scans")
    axis.grid(axis="y", linestyle="--", alpha=0.5)
    axis.bar_label(bars)
    output_directory = os.path.join(os.path.dirname(__file__), "visualizations")
    os.makedirs(output_directory, exist_ok=True)
    output_path = os.path.join(output_directory, "threat_distribution.png")
    figure.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close(figure)
    return output_path


def handle_statistics():
    print("\n" + "=" * 55)
    print("              [ SCAN STATISTICS ]")
    print("=" * 55)
    try:
        stats = get_stats()
        records = get_history()
    except (OSError, TypeError, ValueError) as error:
        print(f"\n[!] Could not read scan statistics: {error}\n")
        return
    if not stats["total_scans"]:
        print("\n[*] No scan data available yet to compute statistics.\n")
        return

    url_scans = sum(record.get("type") == "URL" for record in records)
    message_scans = sum(record.get("type") == "Message" for record in records)
    print(f"\nTotal Scans Analyzed : {stats['total_scans']}")
    print(f"  - URL Scans         : {url_scans}")
    print(f"  - Message Scans     : {message_scans}")
    print(f"Average Risk Score    : {stats['average_score']} / 100")
    print("\nThreat Level Distribution:")
    for level, count in stats["counts_per_level"].items():
        percentage = count / stats["total_scans"] * 100
        bars = "#" * int(percentage // 5)
        print(f"  {level:<8}: {count:>3} ({percentage:>5.1f}%) | {bars}")
    print("-" * 55)

    export_choice = input("\nWould you like to export a visual chart image? (y/n): ").strip().lower()
    if export_choice in ("y", "yes"):
        chart_file = _save_threat_distribution_chart(stats["counts_per_level"])
        print(f"[*] Visual chart saved to: {chart_file}\n")
    else:
        print()


def main():
    display_banner()
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
            break
        else:
            print("\n[!] Invalid choice. Please enter a number from 1 to 5.\n")


if __name__ == "__main__":
    main()
