"""Local benchmark for the static rules against labeled CSV cases."""

import csv
import os

from engine.risk_engine import calculate_risk_score, classify_threat
from scanners.message_scanner import scan_message
from scanners.url_scanner import scan_url

THREAT_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
EXPECTED_FIELDS = {"input_type", "input", "expected_threat_level", "description"}


def _dataset_path():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, "..", "data", "test_cases.csv")


def evaluate_dataset(path=None):
    """Return accuracy and confusion metrics; this does not use live reputation."""
    dataset_path = path or _dataset_path()
    confusion = {actual: {predicted: 0 for predicted in THREAT_LEVELS} for actual in THREAT_LEVELS}
    binary = {"true_positive": 0, "false_positive": 0, "true_negative": 0, "false_negative": 0}
    total = 0
    correct = 0

    with open(dataset_path, mode="r", newline="", encoding="utf-8") as dataset:
        reader = csv.DictReader(dataset, strict=True)
        if not reader.fieldnames or set(reader.fieldnames) != EXPECTED_FIELDS:
            raise ValueError(
                "Benchmark CSV must contain input_type,input,expected_threat_level,description"
            )
        for line_number, row in enumerate(reader, start=2):
            input_type = (row.get("input_type") or "").strip().lower()
            raw_input = row.get("input")
            expected = (row.get("expected_threat_level") or "").strip().upper()
            if input_type not in {"url", "message"} or not raw_input:
                raise ValueError(f"Invalid benchmark input on line {line_number}")
            if expected not in THREAT_LEVELS:
                raise ValueError(f"Invalid expected threat level on line {line_number}")

            if input_type == "url":
                indicators = scan_url(raw_input)
            else:
                result = scan_message(raw_input)
                indicators = list(result["message_indicators"])
                for embedded_url in result["extracted_urls"]:
                    indicators.extend(scan_url(embedded_url))

            predicted = classify_threat(calculate_risk_score(indicators))
            confusion[expected][predicted] += 1
            total += 1
            correct += expected == predicted

            expected_alert = expected != "LOW"
            predicted_alert = predicted != "LOW"
            if expected_alert and predicted_alert:
                binary["true_positive"] += 1
            elif not expected_alert and predicted_alert:
                binary["false_positive"] += 1
            elif not expected_alert and not predicted_alert:
                binary["true_negative"] += 1
            else:
                binary["false_negative"] += 1

    if not total:
        raise ValueError("Benchmark dataset is empty")

    positive_predictions = binary["true_positive"] + binary["false_positive"]
    actual_positives = binary["true_positive"] + binary["false_negative"]
    precision = binary["true_positive"] / positive_predictions if positive_predictions else 0.0
    recall = binary["true_positive"] / actual_positives if actual_positives else 0.0
    return {
        "total": total,
        "accuracy": correct / total,
        "confusion_matrix": confusion,
        "binary_alert_metrics": {
            **binary,
            "precision": precision,
            "recall": recall,
        },
        "scope": "static heuristic only; LOW is treated as negative and all higher levels as positive",
    }


def print_report(report):
    """Print a concise benchmark report."""
    print(f"Cases: {report['total']}")
    print(f"Exact threat-level accuracy: {report['accuracy']:.1%}")
    print("Binary alert metrics (LOW = negative; MEDIUM/HIGH/CRITICAL = positive):")
    metrics = report["binary_alert_metrics"]
    print(f"  Precision: {metrics['precision']:.1%}")
    print(f"  Recall   : {metrics['recall']:.1%}")
    print(f"  False positives: {metrics['false_positive']}")
    print(f"  False negatives: {metrics['false_negative']}")
    print("Confusion matrix (rows=expected, columns=predicted):")
    print("                 " + " ".join(f"{level:>9}" for level in THREAT_LEVELS))
    for expected in THREAT_LEVELS:
        counts = " ".join(f"{report['confusion_matrix'][expected][level]:>9}" for level in THREAT_LEVELS)
        print(f"  {expected:<14}{counts}")
    print("\nThese results describe only this small, hand-authored regression set.")
    print("They are not a measure of real-world phishing detection performance.")


def main():
    print_report(evaluate_dataset())


if __name__ == "__main__":
    main()
