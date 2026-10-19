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


def display_banner():
    """
    Print the PhishGuard welcome banner.

    Takes:   Nothing.
    Returns: Nothing (just prints to screen).
    Why:     A clear banner tells the user what app they're using
             and makes the CLI feel polished.
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
    Why:     Showing numbered options makes it easy for the user
             to pick what they want to do. Each number maps to
             one feature of the app.
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
    Returns: An integer (1-5) if the input is valid,
             or -1 if the input was not a number.
    Why:     We wrap input() in try/except so that typing "abc"
             doesn't crash the program with a ValueError.
    """
    try:
        # strip() removes accidental spaces before/after the number
        choice = int(input("Enter your choice (1-5): ").strip())
        return choice
    except ValueError:
        # If the user types something that isn't a number,
        # we return -1 so the main loop can show an error message.
        return -1


def handle_url_scan():
    """
    Handle option 1: Scan a URL for phishing indicators.

    Takes:   Nothing (will read URL from user in future tasks).
    Returns: Nothing.
    Why:     This is a placeholder. In Task 3+, it will call
             url_scanner functions, compute risk, and show results.
    """
    print("\n[URL Scanner] - Not implemented yet.")
    print("This will analyze a URL for phishing indicators.\n")


def handle_message_scan():
    """
    Handle option 2: Scan a text message for phishing indicators.

    Takes:   Nothing (will read message from user in future tasks).
    Returns: Nothing.
    Why:     This is a placeholder. In Task 3+, it will call
             message_scanner functions, compute risk, and show results.
    """
    print("\n[Message Scanner] - Not implemented yet.")
    print("This will analyze a text message for phishing clues.\n")


def handle_view_history():
    """
    Handle option 3: Show past scan results from CSV.

    Takes:   Nothing.
    Returns: Nothing.
    Why:     Placeholder for viewing saved scan history.
             Will read from data/scan_history.csv later.
    """
    print("\n[Scan History] - Not implemented yet.")
    print("This will show your past scan results.\n")


def handle_statistics():
    """
    Handle option 4: Show summary statistics of all scans.

    Takes:   Nothing.
    Returns: Nothing.
    Why:     Placeholder for statistics and charts.
             Will use pandas and matplotlib later.
    """
    print("\n[Statistics] - Not implemented yet.")
    print("This will show charts and stats about your scans.\n")


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
