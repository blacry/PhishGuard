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


import os
import csv
from datetime import datetime


def _get_history_path():
    """
    Helper function to get the absolute path to data/scan_history.csv.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, "..", "data", "scan_history.csv")


def save_scan(scan_result):
    """
    Save a single scan result to the CSV history file.

    Takes:   scan_result (dict) - must contain:
             {"input_type": str, "input": str,
              "risk_score": int, "threat_level": str, "indicators": str}
             Optional: "timestamp" (defaults to current time if missing).
    Returns: bool - True if saved successfully, False if there was an error.

    How it works:
        1. Open data/scan_history.csv in append mode ("a").
        2. If the file is newly created or empty, write the CSV header row.
        3. Write one new row containing the scan record.
        4. Close the file cleanly.
    """
    if not isinstance(scan_result, dict):
        return False

    history_path = _get_history_path()
    fieldnames = ["timestamp", "input_type", "input", "risk_score", "threat_level", "indicators"]

    # Provide automatic timestamp if omitted
    timestamp = scan_result.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Sanitize input: truncate long messages to keep CSV readable,
    # and ensure clean one-line representation (replace newlines)
    raw_input = str(scan_result.get("input", "")).replace("\n", " ").strip()
    if len(raw_input) > 80:
        clean_input = raw_input[:77] + "..."
    else:
        clean_input = raw_input

    row_data = {
        "timestamp": timestamp,
        "input_type": str(scan_result.get("input_type", "unknown")),
        "input": clean_input,
        "risk_score": int(scan_result.get("risk_score", 0)),
        "threat_level": str(scan_result.get("threat_level", "LOW")),
        "indicators": str(scan_result.get("indicators", ""))
    }

    try:
        # Check if file exists and has content to know if header is needed
        file_exists = os.path.exists(history_path)
        is_empty = (os.path.getsize(history_path) == 0) if file_exists else True

        with open(history_path, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if is_empty:
                writer.writeheader()
            writer.writerow(row_data)

        return True
    except Exception:
        # Fail gracefully if file permissions or filesystem prevents write
        return False


def load_scan_history():
    """
    Read all past scan results from data/scan_history.csv.

    Takes:   Nothing.
    Returns: list of dicts - each dict represents one scan record.
             Returns empty list if file doesn't exist or is empty.
    """
    history_path = _get_history_path()
    if not os.path.exists(history_path):
        return []

    records = []
    try:
        with open(history_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                records.append(row)
    except Exception:
        return []

    return records


def generate_statistics():
    """
    Read scan history and compute summary statistics.

    Takes:   Nothing (reads from data/scan_history.csv).
    Returns: dict - {"total_scans": int,
                      "url_scans": int,
                      "message_scans": int,
                      "average_risk_score": float,
                      "threat_distribution": {"LOW": n, "MEDIUM": n,
                                              "HIGH": n, "CRITICAL": n}}
             Returns None if no history exists.
    """
    records = load_scan_history()
    if not records:
        return None

    total_scans = len(records)
    url_scans = 0
    message_scans = 0
    total_score = 0
    threat_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    for r in records:
        itype = r.get("input_type", "").lower()
        if itype == "url":
            url_scans += 1
        elif itype == "message":
            message_scans += 1

        try:
            score = int(r.get("risk_score", 0))
        except (ValueError, TypeError):
            score = 0
        total_score += score

        level = r.get("threat_level", "LOW").upper()
        if level in threat_dist:
            threat_dist[level] += 1
        else:
            threat_dist["LOW"] += 1

    avg_score = round(total_score / total_scans, 1) if total_scans > 0 else 0.0

    return {
        "total_scans": total_scans,
        "url_scans": url_scans,
        "message_scans": message_scans,
        "average_risk_score": avg_score,
        "threat_distribution": threat_dist
    }


def save_threat_distribution_chart(output_path=None):
    """
    Generate and save visual analytics charts using matplotlib and pandas.
    Saves a clean two-panel chart (Threat Distribution Bar Chart + Scan Types Pie Chart)
    to visualizations/threat_distribution.png.

    Takes:   output_path (str, optional) - custom save location.
    Returns: str - path to saved image file, or None if no data to plot.
    """
    records = load_scan_history()
    if not records:
        return None

    import matplotlib
    matplotlib.use("Agg")  # Non-interactive backend safe for CLI scripts
    import matplotlib.pyplot as plt
    import pandas as pd

    current_dir = os.path.dirname(os.path.abspath(__file__))
    if not output_path:
        viz_dir = os.path.join(current_dir, "..", "visualizations")
        os.makedirs(viz_dir, exist_ok=True)
        output_path = os.path.join(viz_dir, "threat_distribution.png")

    df = pd.DataFrame(records)

    # Convert risk_score to numeric
    df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce").fillna(0)

    # Prepare Threat Distribution counts
    levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    counts = [sum(df["threat_level"].str.upper() == lvl) for lvl in levels]
    colors = ["#2ecc71", "#f39c12", "#e67e22", "#e74c3c"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle("PhishGuard Security Analytics", fontsize=16, fontweight="bold", y=1.02)

    # 1. Bar Chart: Threat Levels
    bars = ax1.bar(levels, counts, color=colors, edgecolor="#333333", linewidth=1.2)
    ax1.set_title("Threat Level Classification", fontsize=12, pad=10)
    ax1.set_ylabel("Number of Scans", fontsize=10)
    ax1.set_xlabel("Threat Level", fontsize=10)
    ax1.grid(axis="y", linestyle="--", alpha=0.5)

    # Add numeric labels on top of bars
    for bar in bars:
        height = bar.get_height()
        ax1.annotate(f"{int(height)}",
                     xy=(bar.get_x() + bar.get_width() / 2, height),
                     xytext=(0, 3),
                     textcoords="offset points",
                     ha="center", va="bottom", fontsize=10, fontweight="bold")

    # 2. Pie Chart: Input Type Distribution
    type_counts = df["input_type"].str.lower().value_counts()
    labels = [t.title() for t in type_counts.index]
    ax2.pie(type_counts, labels=labels, autopct="%1.1f%%", startangle=140,
            colors=["#3498db", "#9b59b6"][:len(type_counts)],
            wedgeprops={"edgecolor": "#333333", "linewidth": 1.2})
    ax2.set_title("Scans by Input Type", fontsize=12, pad=10)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()

    return output_path


