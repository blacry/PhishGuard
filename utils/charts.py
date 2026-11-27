"""Chart exports for local scan history."""

import os

from utils.helpers import load_scan_history


def save_threat_distribution_chart(output_path=None):
    """Save threat and input-type charts, returning None when history is empty."""
    records = load_scan_history()
    if not records:
        return None

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    current_dir = os.path.dirname(os.path.abspath(__file__))
    if not output_path:
        visualization_dir = os.path.join(current_dir, "..", "visualizations")
        os.makedirs(visualization_dir, exist_ok=True)
        output_path = os.path.join(
            visualization_dir, "threat_distribution.png"
        )

    levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    threat_counts = dict.fromkeys(levels, 0)
    type_counts = {}
    for record in records:
        level = str(record.get("threat_level", "")).upper()
        if level in threat_counts:
            threat_counts[level] += 1
        input_type = str(record.get("input_type", "unknown")).lower()
        type_counts[input_type] = type_counts.get(input_type, 0) + 1

    threat_colors = ["#2ecc71", "#f39c12", "#e67e22", "#e74c3c"]
    type_colors = {"url": "#3498db", "message": "#9b59b6"}
    input_types = sorted(type_counts)

    figure, (threat_axis, type_axis) = plt.subplots(1, 2, figsize=(12, 5))
    figure.suptitle(
        "PhishGuard Security Analytics", fontsize=16, fontweight="bold", y=1.02
    )

    bars = threat_axis.bar(
        levels,
        [threat_counts[level] for level in levels],
        color=threat_colors,
        edgecolor="#333333",
        linewidth=1.2,
    )
    threat_axis.set_title("Threat Level Classification", fontsize=12, pad=10)
    threat_axis.set_ylabel("Number of Scans", fontsize=10)
    threat_axis.set_xlabel("Threat Level", fontsize=10)
    threat_axis.grid(axis="y", linestyle="--", alpha=0.5)

    for bar in bars:
        height = bar.get_height()
        threat_axis.annotate(
            f"{int(height)}",
            xy=(bar.get_x() + bar.get_width() / 2, height),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight="bold",
        )

    type_axis.pie(
        [type_counts[input_type] for input_type in input_types],
        labels=[input_type.title() for input_type in input_types],
        autopct="%1.1f%%",
        startangle=140,
        colors=[type_colors.get(input_type, "#95a5a6") for input_type in input_types],
        wedgeprops={"edgecolor": "#333333", "linewidth": 1.2},
    )
    type_axis.set_title("Scans by Input Type", fontsize=12, pad=10)

    figure.tight_layout()
    figure.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close(figure)
    return output_path
