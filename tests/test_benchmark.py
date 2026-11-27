from utils.benchmark import evaluate_dataset


def test_benchmark_evaluates_all_labeled_cases():
    report = evaluate_dataset()
    metrics = report["binary_alert_metrics"]

    assert report["total"] == 10
    assert report["accuracy"] == 1.0
    assert metrics["true_positive"] > 0
    assert metrics["true_negative"] > 0
    assert metrics["false_positive"] == 0
    assert metrics["false_negative"] == 0
