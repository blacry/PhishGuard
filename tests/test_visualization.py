from utils import charts


def test_chart_is_saved_from_history_without_pandas(monkeypatch, tmp_path):
    records = [
        {"threat_level": "LOW", "input_type": "url"},
        {"threat_level": "CRITICAL", "input_type": "message"},
        {"threat_level": "HIGH", "input_type": "unknown"},
    ]
    output_path = tmp_path / "threat_distribution.png"
    monkeypatch.setattr(charts, "load_scan_history", lambda: records)

    result = charts.save_threat_distribution_chart(str(output_path))

    assert result == str(output_path)
    assert output_path.is_file()
    assert output_path.stat().st_size > 0
