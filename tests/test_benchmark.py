import pytest

from utils.benchmark import (
    _analyze_score_thresholds,
    _holdout_partition,
    _new_score_histograms,
    _projected_precision,
    evaluate_dataset,
    main,
)


def test_benchmark_evaluates_all_labeled_cases():
    report = evaluate_dataset()
    metrics = report["binary_alert_metrics"]

    assert report["total"] == 10
    assert report["accuracy"] == 1.0
    assert metrics["true_positive"] > 0
    assert metrics["true_negative"] > 0
    assert metrics["false_positive"] == 0
    assert metrics["false_negative"] == 0
    assert metrics["false_positive_rate"] == 0.0
    assert set(report["input_type_metrics"]) == {"url", "message"}
    assert report["input_type_metrics"]["url"]["total"] == 5
    assert report["input_type_metrics"]["message"]["total"] == 5


def test_benchmark_accepts_external_dataset_and_reports_by_input_type(
    tmp_path, capsys
):
    dataset = tmp_path / "evaluation.csv"
    dataset.write_text(
        "input_type,input,expected_threat_level,description\n"
        "url,https://example.com,LOW,benign URL\n"
        "message,Hello how are you doing today?,LOW,benign message\n"
        "url,http://192.168.1.1/login,MEDIUM,synthetic suspicious URL\n",
        encoding="utf-8",
    )

    main(["--dataset", str(dataset)])

    output = capsys.readouterr().out
    assert f"Dataset: {dataset}" in output
    assert "url: 2 cases" in output
    assert "message: 1 cases" in output
    assert "False-positive rate: 0.0%" in output
    assert "Dataset provenance and label quality are not verified" in output

    message_metrics = evaluate_dataset(dataset)["input_type_metrics"]["message"]
    assert message_metrics["binary_alert_metrics"]["precision"] == 0.0
    assert message_metrics["binary_alert_metrics"]["recall"] == 0.0
    assert message_metrics["binary_alert_metrics"]["f1"] == 0.0


def test_benchmark_evaluates_phiusiil_binary_labels_without_visiting_urls(
    tmp_path, capsys
):
    dataset = tmp_path / "phiusiil.csv"
    dataset.write_text(
        "URL,label\n"
        "https://example.com,1\n"
        "http://192.168.1.1/login,0\n",
        encoding="utf-8",
    )

    main(["--dataset", str(dataset)])

    report = evaluate_dataset(dataset)
    assert report["dataset_format"] == "phiusiil"
    assert report["label_mode"] == "binary"
    assert report["class_labels"] == ("LEGITIMATE", "PHISHING")
    assert report["accuracy"] == 1.0
    assert report["binary_alert_metrics"]["true_positive"] == 1
    assert report["binary_alert_metrics"]["true_negative"] == 1
    output = capsys.readouterr().out
    assert "Binary classification accuracy: 100.0%" in output
    assert "UCI label mapping: 0=PHISHING, 1=LEGITIMATE." in output
    assert "url: 2 cases, 100.0% binary accuracy" in output


def test_benchmark_maps_prepared_kaggle_phishguard_source_labels(tmp_path, capsys):
    hosts = {}
    index = 0
    for partition in ("development", "holdout"):
        while partition not in hosts:
            hostname = f"host-{index}.example"
            hosts[_holdout_partition(f"https://{hostname}/")] = hostname
            index += 1
    dataset = tmp_path / "kaggle.csv"
    rows = ["input_type,input,expected_threat_level,description"]
    for partition, hostname in hosts.items():
        for level, label in (
            ("LOW", "benign"),
            ("MEDIUM", "phishing"),
        ):
            rows.append(
                f"url,https://{hostname}/{label},{level},"
                f"Kaggle source label: {label}"
            )
    dataset.write_text("\n".join(rows) + "\n", encoding="utf-8")

    main(["--dataset", str(dataset)])

    report = evaluate_dataset(dataset)
    assert report["dataset_format"] == "kaggle_phishguard"
    assert report["label_mode"] == "binary"
    assert report["total"] == 4
    assert sum(report["confusion_matrix"]["PHISHING"].values()) == 2
    assert sum(report["confusion_matrix"]["LEGITIMATE"].values()) == 2
    assert report["threshold_analysis"]["available"]
    output = capsys.readouterr().out
    assert "Kaggle source label mapping: phishing=PHISHING, benign=LEGITIMATE." in output


def test_benchmark_rejects_unknown_phiusiil_labels(tmp_path):
    dataset = tmp_path / "invalid_phiusiil.csv"
    dataset.write_text("URL,label\nhttps://example.com,2\n", encoding="utf-8")

    with pytest.raises(ValueError, match="expected 0 or 1"):
        evaluate_dataset(dataset)


def test_holdout_split_keeps_a_hostname_together():
    assert _holdout_partition("https://example.com/login") == _holdout_partition(
        "http://example.com/account"
    )


def test_score_threshold_is_selected_on_development_not_holdout():
    histograms = _new_score_histograms()
    histograms["development"]["LEGITIMATE"][0] = 10
    histograms["development"]["PHISHING"][10] = 10
    histograms["holdout"]["LEGITIMATE"][10] = 10
    histograms["holdout"]["PHISHING"][0] = 10

    analysis = _analyze_score_thresholds(histograms)

    assert analysis["selected_threshold"] == 10
    assert analysis["development_selected"]["f1"] == 1.0
    assert analysis["holdout_selected"]["f1"] == 0.0
    assert analysis["holdout_selected"]["false_positive_rate"] == 1.0


def test_projected_precision_reflects_assumed_phishing_prevalence():
    precision_at_one_percent = _projected_precision(
        recall=0.643,
        false_positive_rate=0.015,
        prevalence=0.01,
    )

    assert precision_at_one_percent == pytest.approx(0.3022, abs=0.0001)
    assert _projected_precision(0.0, 0.0, 0.01) == 0.0
