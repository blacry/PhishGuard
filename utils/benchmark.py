"""Local benchmark for the static rules against labeled CSV cases."""

import argparse
import csv
import hashlib
from itertools import chain
import os
from urllib.parse import urlsplit

from engine.risk_engine import calculate_risk_score, classify_threat
from scanners.message_scanner import scan_message
from scanners.url_scanner import scan_url

THREAT_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
BINARY_LABELS = ("LEGITIMATE", "PHISHING")
EXPECTED_FIELDS = {"input_type", "input", "expected_threat_level", "description"}
PHIUSIIL_REQUIRED_FIELDS = {"URL", "label"}
KAGGLE_SOURCE_LABELS = {
    "Kaggle source label: benign": "LEGITIMATE",
    "Kaggle source label: phishing": "PHISHING",
}
CURRENT_ALERT_THRESHOLD = 25
ILLUSTRATIVE_PHISHING_PREVALENCES = (0.001, 0.01, 0.05, 0.10)


def _dataset_path():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, "..", "data", "test_cases.csv")


def _new_metrics_bucket(class_labels):
    return {
        "total": 0,
        "correct": 0,
        "confusion_matrix": {
            actual: {predicted: 0 for predicted in class_labels}
            for actual in class_labels
        },
        "binary": {
            "true_positive": 0,
            "false_positive": 0,
            "true_negative": 0,
            "false_negative": 0,
        },
    }


def _record_prediction(bucket, expected, predicted, label_mode):
    bucket["total"] += 1
    bucket["correct"] += expected == predicted
    bucket["confusion_matrix"][expected][predicted] += 1

    if label_mode == "binary":
        expected_alert = expected == "PHISHING"
        predicted_alert = predicted == "PHISHING"
    else:
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
    legitimate_cases = binary["true_negative"] + binary["false_positive"]
    false_positive_rate = (
        binary["false_positive"] / legitimate_cases if legitimate_cases else 0.0
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
            "false_positive_rate": false_positive_rate,
            "f1": f1,
        },
    }


def _holdout_partition(url):
    """Keep the same hostname in one deterministic development/holdout split."""
    try:
        hostname = urlsplit(url).hostname
    except ValueError:
        hostname = None
    group_key = hostname.lower().rstrip(".") if hostname else url.strip().lower()
    partition = int.from_bytes(
        hashlib.sha256(group_key.encode("utf-8")).digest()[:8], "big"
    ) % 5
    return "holdout" if partition == 0 else "development"


def _new_score_histograms():
    return {
        partition: {label: [0] * 101 for label in BINARY_LABELS}
        for partition in ("development", "holdout")
    }


def _threshold_metrics(histogram, threshold):
    phishing_scores = histogram["PHISHING"]
    legitimate_scores = histogram["LEGITIMATE"]
    true_positive = sum(phishing_scores[threshold:])
    false_negative = sum(phishing_scores[:threshold])
    false_positive = sum(legitimate_scores[threshold:])
    true_negative = sum(legitimate_scores[:threshold])
    total = true_positive + false_negative + false_positive + true_negative

    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    legitimate_count = false_positive + true_negative
    precision = true_positive / precision_denominator if precision_denominator else 0.0
    recall = true_positive / recall_denominator if recall_denominator else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "threshold": threshold,
        "cases": total,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "true_negative": true_negative,
        "false_negative": false_negative,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": (
            false_positive / legitimate_count if legitimate_count else 0.0
        ),
    }


def _projected_precision(recall, false_positive_rate, prevalence):
    true_alert_rate = recall * prevalence
    false_alert_rate = false_positive_rate * (1 - prevalence)
    total_alert_rate = true_alert_rate + false_alert_rate
    return true_alert_rate / total_alert_rate if total_alert_rate else 0.0


def _analyze_score_thresholds(score_histograms):
    development = score_histograms["development"]
    holdout = score_histograms["holdout"]
    development_cases = sum(sum(scores) for scores in development.values())
    holdout_cases = sum(sum(scores) for scores in holdout.values())
    if not development_cases or not holdout_cases:
        return {
            "available": False,
            "reason": "The deterministic split needs cases in both partitions.",
        }

    selected_threshold = max(
        range(101),
        key=lambda threshold: (
            _threshold_metrics(development, threshold)["f1"],
            _threshold_metrics(development, threshold)["precision"],
            threshold,
        ),
    )
    holdout_selected = _threshold_metrics(holdout, selected_threshold)
    return {
        "available": True,
        "split_method": "SHA-256 hostname grouping; 1 of 5 buckets held out",
        "development_cases": development_cases,
        "holdout_cases": holdout_cases,
        "baseline_threshold": CURRENT_ALERT_THRESHOLD,
        "selected_threshold": selected_threshold,
        "development_baseline": _threshold_metrics(
            development, CURRENT_ALERT_THRESHOLD
        ),
        "holdout_baseline": _threshold_metrics(holdout, CURRENT_ALERT_THRESHOLD),
        "development_selected": _threshold_metrics(development, selected_threshold),
        "holdout_selected": holdout_selected,
        "selected_holdout_prevalence_scenarios": [
            {
                "assumed_phishing_prevalence": prevalence,
                "projected_precision": _projected_precision(
                    holdout_selected["recall"],
                    holdout_selected["false_positive_rate"],
                    prevalence,
                ),
            }
            for prevalence in ILLUSTRATIVE_PHISHING_PREVALENCES
        ],
    }


def evaluate_dataset(path=None):
    """Evaluate PhishGuard cases or supported external URL labels."""
    dataset_path = os.path.abspath(path or _dataset_path())
    with open(dataset_path, mode="r", newline="", encoding="utf-8-sig") as dataset:
        reader = csv.DictReader(dataset, strict=True)
        fields = set(reader.fieldnames or ())
        if fields == EXPECTED_FIELDS:
            dataset_format = "phishguard"
            label_mode = "threat_level"
            class_labels = THREAT_LEVELS
        elif PHIUSIIL_REQUIRED_FIELDS.issubset(fields):
            dataset_format = "phiusiil"
            label_mode = "binary"
            class_labels = BINARY_LABELS
        else:
            raise ValueError(
                "Benchmark CSV must use the PhishGuard schema "
                "(input_type,input,expected_threat_level,description) or "
                "contain UCI PhiUSIIL URL and label columns"
            )

        rows = iter(reader)
        first_row = next(rows, None)
        kaggle_format = (
            dataset_format == "phishguard"
            and first_row is not None
            and first_row.get("description") in KAGGLE_SOURCE_LABELS
        )
        if kaggle_format:
            dataset_format = "kaggle_phishguard"
            label_mode = "binary"
            class_labels = BINARY_LABELS

        overall = _new_metrics_bucket(class_labels)
        by_input_type = {}
        score_histograms = (
            _new_score_histograms() if label_mode == "binary" else None
        )
        for line_number, row in enumerate(
            chain(() if first_row is None else (first_row,), rows), start=2
        ):
            if dataset_format == "phiusiil":
                input_type = "url"
                raw_input = row.get("URL") or ""
                source_label = (row.get("label") or "").strip()
                if source_label not in {"0", "1"}:
                    raise ValueError(
                        f"Invalid PhiUSIIL label on line {line_number}: expected 0 or 1"
                    )
                expected = "PHISHING" if source_label == "0" else "LEGITIMATE"
            elif dataset_format == "kaggle_phishguard":
                input_type = (row.get("input_type") or "").strip().lower()
                raw_input = row.get("input") or ""
                source_label = row.get("description") or ""
                expected = KAGGLE_SOURCE_LABELS.get(source_label)
                if expected is None:
                    raise ValueError(
                        f"Invalid Kaggle source label on line {line_number}: "
                        "expected the benign or phishing source label"
                    )
                if input_type != "url":
                    raise ValueError(
                        f"Invalid Kaggle benchmark input type on line {line_number}: "
                        "expected url"
                    )
            else:
                input_type = (row.get("input_type") or "").strip().lower()
                raw_input = row.get("input") or ""
                expected = (row.get("expected_threat_level") or "").strip().upper()
                if input_type not in {"url", "message"}:
                    raise ValueError(f"Invalid benchmark input type on line {line_number}")
                if expected not in THREAT_LEVELS:
                    raise ValueError(f"Invalid expected threat level on line {line_number}")

            if not raw_input.strip():
                raise ValueError(f"Missing benchmark input on line {line_number}")

            if input_type == "url":
                indicators = scan_url(raw_input)
            else:
                result = scan_message(raw_input)
                indicators = list(result["message_indicators"])
                for embedded_url in result["extracted_urls"]:
                    indicators.extend(scan_url(embedded_url))

            score = calculate_risk_score(indicators)
            predicted_threat = classify_threat(score)
            if score_histograms is not None:
                partition = _holdout_partition(raw_input)
                score_histograms[partition][expected][score] += 1
            predicted = (
                ("PHISHING" if predicted_threat != "LOW" else "LEGITIMATE")
                if label_mode == "binary"
                else predicted_threat
            )
            _record_prediction(overall, expected, predicted, label_mode)
            input_type_bucket = by_input_type.setdefault(
                input_type, _new_metrics_bucket(class_labels)
            )
            _record_prediction(input_type_bucket, expected, predicted, label_mode)

        if not overall["total"]:
            raise ValueError("Benchmark dataset is empty")

    summary = _summarize_bucket(overall)
    threshold_analysis = (
        _analyze_score_thresholds(score_histograms)
        if score_histograms is not None
        else None
    )
    return {
        **summary,
        "dataset_path": dataset_path,
        "dataset_format": dataset_format,
        "label_mode": label_mode,
        "class_labels": class_labels,
        "input_type_metrics": {
            input_type: _summarize_bucket(bucket)
            for input_type, bucket in sorted(by_input_type.items())
        },
        "threshold_analysis": threshold_analysis,
        "scope": "static heuristic only; submitted URLs are never visited",
    }


def print_report(report):
    """Print aggregate and per-input-type benchmark metrics."""
    print(f"Dataset: {report['dataset_path']}")
    print(f"Cases: {report['total']}")
    if report["label_mode"] == "binary":
        print(f"Binary classification accuracy: {report['accuracy']:.1%}")
        print("Positive class: PHISHING; any non-LOW threat level is an alert.")
        if report["dataset_format"] == "phiusiil":
            print("UCI label mapping: 0=PHISHING, 1=LEGITIMATE.")
        elif report["dataset_format"] == "kaggle_phishguard":
            print("Kaggle source label mapping: phishing=PHISHING, benign=LEGITIMATE.")
    else:
        print(f"Exact threat-level accuracy: {report['accuracy']:.1%}")
        print("Binary alert metrics (LOW = negative; all higher levels = positive):")
    metrics = report["binary_alert_metrics"]
    print(f"  Precision: {metrics['precision']:.1%}")
    print(f"  Recall   : {metrics['recall']:.1%}")
    print(f"  False-positive rate: {metrics['false_positive_rate']:.1%}")
    print(f"  F1 score : {metrics['f1']:.1%}")
    print(f"  False positives: {metrics['false_positive']}")
    print(f"  False negatives: {metrics['false_negative']}")
    print("Metrics by input type:")
    accuracy_label = (
        "binary accuracy"
        if report["label_mode"] == "binary"
        else "exact accuracy"
    )
    for input_type, type_metrics in report["input_type_metrics"].items():
        type_alert = type_metrics["binary_alert_metrics"]
        print(
            f"  {input_type}: {type_metrics['total']} cases, "
            f"{type_metrics['accuracy']:.1%} {accuracy_label}, "
            f"{type_alert['precision']:.1%} alert precision, "
            f"{type_alert['recall']:.1%} alert recall, "
            f"{type_alert['f1']:.1%} F1"
        )
    class_labels = report["class_labels"]
    print("Confusion matrix (rows=expected, columns=predicted):")
    print("                 " + " ".join(f"{label:>12}" for label in class_labels))
    for expected in class_labels:
        counts = " ".join(
            f"{report['confusion_matrix'][expected][label]:>12}"
            for label in class_labels
        )
        print(f"  {expected:<14}{counts}")
    threshold_analysis = report["threshold_analysis"]
    if threshold_analysis is not None:
        print("\nScore-threshold analysis (evaluation only; not applied to the scanner):")
        if not threshold_analysis["available"]:
            print(f"  Skipped: {threshold_analysis['reason']}")
        else:
            print(f"  Split: {threshold_analysis['split_method']}")
            print(
                f"  Cases: {threshold_analysis['development_cases']} development, "
                f"{threshold_analysis['holdout_cases']} holdout"
            )
            for name, result_key in (
                ("Current", "baseline"),
                ("Development-best F1", "selected"),
            ):
                threshold = threshold_analysis[
                    "baseline_threshold" if result_key == "baseline"
                    else "selected_threshold"
                ]
                development = threshold_analysis[f"development_{result_key}"]
                holdout = threshold_analysis[f"holdout_{result_key}"]
                print(
                    f"  {name} cutoff >= {threshold}: "
                    f"development F1 {development['f1']:.1%}, "
                    f"FPR {development['false_positive_rate']:.1%}; "
                    f"holdout precision {holdout['precision']:.1%}, "
                    f"recall {holdout['recall']:.1%}, F1 {holdout['f1']:.1%}, "
                    f"FPR {holdout['false_positive_rate']:.1%}, "
                    f"FP {holdout['false_positive']}, FN {holdout['false_negative']}"
                )
            print(
                "  Development-best cutoff precision at illustrative phishing "
                "prevalences (holdout recall/FPR point estimates):"
            )
            for scenario in threshold_analysis[
                "selected_holdout_prevalence_scenarios"
            ]:
                print(
                    f"    {scenario['assumed_phishing_prevalence']:.1%}: "
                    f"{scenario['projected_precision']:.1%}"
                )
            print(
                "  These are sensitivity scenarios, not measurements of actual "
                "traffic prevalence or production precision."
            )
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
        help=(
            "Path to a labeled CSV (PhishGuard schema, UCI PhiUSIIL URL/label, "
            "or prepared Kaggle PhishGuard labels); defaults to the built-in set"
        ),
    )
    args = parser.parse_args(argv)
    print_report(evaluate_dataset(args.dataset))


if __name__ == "__main__":
    main()
