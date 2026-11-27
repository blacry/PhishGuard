from utils.benchmark import evaluate_dataset, main


def test_benchmark_evaluates_all_labeled_cases():
    report = evaluate_dataset()
    metrics = report["binary_alert_metrics"]

    assert report["total"] == 10
    assert report["accuracy"] == 1.0
    assert metrics["true_positive"] > 0
    assert metrics["true_negative"] > 0
    assert metrics["false_positive"] == 0
    assert metrics["false_negative"] == 0
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
    assert "Dataset provenance and label quality are not verified" in output

    message_metrics = evaluate_dataset(dataset)["input_type_metrics"]["message"]
    assert message_metrics["binary_alert_metrics"]["precision"] == 0.0
    assert message_metrics["binary_alert_metrics"]["recall"] == 0.0
    assert message_metrics["binary_alert_metrics"]["f1"] == 0.0
