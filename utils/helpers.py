"""
helpers.py — Utility functions for file I/O and statistics.

This module handles "side tasks" that aren't part of the core
detection logic but are essential for the app to work:
    - Saving scan results to a CSV file (persistent history)
    - Reading scan history back from the CSV
    - Generating summary statistics from past scans

Python concepts used:
    - File handling (open, read, write) with the csv module
    - os.path for file path management
    - datetime for timestamps
    - Basic math for statistics (count, average)
"""


def save_scan(scan_result):
    """
    Save a single scan result to the CSV history file.

    Takes:   scan_result (dict) — must contain:
             {"timestamp": str, "input_type": str, "input": str,
              "risk_score": int, "threat_level": str, "indicators": str}
    Returns: bool — True if saved successfully, False if there was an error.

    How it works:
        1. Open data/scan_history.csv in append mode ("a").
        2. Write one new row with the scan data.
        3. Close the file.

    Why append mode?
        "w" mode would erase previous scans every time. "a" mode adds
        to the end, preserving all history. Think of it like a logbook.

    Why return bool?
        So the caller knows if saving worked. If the file is locked or
        the disk is full, we return False instead of crashing.
    """
    pass


def generate_statistics():
    """
    Read scan history and compute summary statistics.

    Takes:   Nothing (reads from data/scan_history.csv).
    Returns: dict — {"total_scans": int,
                      "url_scans": int,
                      "message_scans": int,
                      "average_risk_score": float,
                      "threat_distribution": {"LOW": n, "MEDIUM": n,
                                              "HIGH": n, "CRITICAL": n}}
             Returns None if no history exists.

    Why this exists:
        Statistics help the user see patterns: "Am I getting more
        phishing attempts? Are they mostly HIGH or LOW risk?"
        This data can also be visualized with matplotlib later.
    """
    pass
