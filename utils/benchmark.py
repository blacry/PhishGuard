"""Local benchmark for the static rules against labeled CSV cases."""

import argparse
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


def _new_metrics_bucket():
    return {
        "total": 0,
        "correct": 0,
        "confusion_matrix": {
            actual: {predicted: 0 for predicted in THREAT_LEVELS}
            for actual in THREAT_LEVELS
        },
        "binary": {
            "true_positive": 0,
            "false_positive": 0,
            "true_negative": 0,
            "false_negative": 0,
        },
    }


def _record_prediction(bucket, expected, predicted):
    bucket["total"] += 1
    bucket["correct"] += expected == predicted
    bucket["confusion_matrix"][expected][predicted] += 1

    expected_alert = expected != "LOW"
    predicted_alert = predicted != "LOW"
    if expected_alert and predicted_alert:
        bucket["binary"]["true_positive"] += 1
    elif not expected_alert and predicted_alert:
        bucket["binary"]["false_positive"] += 1
    elif not expected_alert and not predicted_alert:
        bucket["binary"]["true_negative"] += 1
    else:
        bucket["binary"]["false_negative"] += 1


def _summarize_bucket(bucket):
    binary = bucket["binary"]
    positive_predictions = binary["true_positive"] + binary["false_positive"]
    actual_positives = binary["true_positive"] + binary["false_negative"]
    precision = (
        binary["true_positive"] / positive_predictions
        if positive_predictions
        else 0.0
    )
    recall = (
        binary["true_positive"] / actual_positives if actual_positives else 0.0
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    return {
        "total": bucket["total"],
        "accuracy": bucket["correct"] / bucket["total"] if bucket["total"] else 0.0,
        "confusion_matrix": bucket["confusion_matrix"],
        "binary_alert_metrics": {
            **binary,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        },
    }


def evaluate_dataset(path=None):
    """Return static-analysis metrics overall and grouped by input type."""
    dataset_path = os.path.abspath(path or _dataset_path())
    overall = _new_metrics_bucket()
    by_input_type = {}

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
            _record_prediction(overall, expected, predicted)
            input_type_bucket = by_input_type.setdefault(
                input_type, _new_metrics_bucket()
            )
            _record_prediction(input_type_bucket, expected, predicted)

    if not overall["total"]:
        raise ValueError("Benchmark dataset is empty")

    summary = _summarize_bucket(overall)
    return {
        **summary,
        "dataset_path": dataset_path,
        "input_type_metrics": {
            input_type: _summarize_bucket(bucket)
            for input_type, bucket in sorted(by_input_type.items())
        },
        "scope": (
            "static heuristic only; LOW is treated as negative and all higher "
            "levels as positive"
        ),
    }


def print_report(report):
    """Print aggregate and per-input-type benchmark metrics."""
    print(f"Dataset: {report['dataset_path']}")
    print(f"Cases: {report['total']}")
    print(f"Exact threat-level accuracy: {report['accuracy']:.1%}")
    print("Binary alert metrics (LOW = negative; MEDIUM/HIGH/CRITICAL = positive):")
    metrics = report["binary_alert_metrics"]
    print(f"  Precision: {metrics['precision']:.1%}")
    print(f"  Recall   : {metrics['recall']:.1%}")
    print(f"  F1 score : {metrics['f1']:.1%}")
    print(f"  False positives: {metrics['false_positive']}")
    print(f"  False negatives: {metrics['false_negative']}")
    print("Metrics by input type:")
    for input_type, type_metrics in report["input_type_metrics"].items():
        type_alert = type_metrics["binary_alert_metrics"]
        print(
            f"  {input_type}: {type_metrics['total']} cases, "
            f"{type_metrics['accuracy']:.1%} exact accuracy, "
            f"{type_alert['precision']:.1%} alert precision, "
            f"{type_alert['recall']:.1%} alert recall, "
            f"{type_alert['f1']:.1%} F1"
        )
    print("Confusion matrix (rows=expected, columns=predicted):")
    print("                 " + " ".join(f"{level:>9}" for level in THREAT_LEVELS))
    for expected in THREAT_LEVELS:
        counts = " ".join(
            f"{report['confusion_matrix'][expected][level]:>9}"
            for level in THREAT_LEVELS
        )
        print(f"  {expected:<14}{counts}")
    if report["dataset_path"] == os.path.abspath(_dataset_path()):
        print("\nThe default dataset is a small, hand-authored regression set.")
    else:
        print("\nResults apply only to the supplied labeled dataset.")
        print("Dataset provenance and label quality are not verified by this tool.")
    print("These results are not, by themselves, a measure of real-world performance.")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Evaluate PhishGuard's static rules on labeled cases."
    )
    parser.add_argument(
        "--dataset",
        help="Path to a labeled CSV; defaults to the small built-in regression set",
    )
    args = parser.parse_args(argv)
    print_report(evaluate_dataset(args.dataset))


if __name__ == "__main__":
    main()
