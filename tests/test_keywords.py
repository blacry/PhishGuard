import csv

from utils.keywords import load_category_keywords, validate_keyword_file


def test_repository_keyword_file_is_valid():
    assert validate_keyword_file() == []
    assert "login" in load_category_keywords(
        "suspicious_url_words", ["fallback"]
    )


def test_keyword_validator_reports_duplicates_and_invalid_rows(tmp_path):
    keyword_path = tmp_path / "keywords.csv"
    with open(keyword_path, "w", newline="", encoding="utf-8") as keyword_file:
        writer = csv.DictWriter(
            keyword_file,
            fieldnames=["category", "keyword", "weight", "description"],
        )
        writer.writeheader()
        writer.writerow({
            "category": "urgency", "keyword": " urgent ", "weight": "10",
            "description": "First entry",
        })
        writer.writerow({
            "category": "urgency", "keyword": "URGENT", "weight": "bad",
            "description": "",
        })

    issues = validate_keyword_file(keyword_path)

    assert any("duplicate keyword" in issue for issue in issues)
    assert any("weight must be an integer" in issue for issue in issues)
    assert any("description is empty" in issue for issue in issues)


def test_loader_refuses_malformed_keyword_file(tmp_path):
    keyword_path = tmp_path / "keywords.csv"
    keyword_path.write_text(
        "category,keyword,weight,description\nurgency,urgent,0,bad weight\n",
        encoding="utf-8",
    )

    try:
        load_category_keywords("urgency", [], keyword_path)
    except ValueError as exc:
        assert "Invalid keyword file" in str(exc)
    else:
        raise AssertionError("Malformed keyword data was accepted")


def test_keyword_loader_refreshes_when_file_changes(tmp_path):
    keyword_path = tmp_path / "keywords.csv"
    keyword_path.write_text(
        "category,keyword,weight,description\n"
        "suspicious_url_words,first,10,first keyword\n",
        encoding="utf-8",
    )

    assert load_category_keywords("suspicious_url_words", [], keyword_path) == [
        "first"
    ]

    keyword_path.write_text(
        "category,keyword,weight,description\n"
        "suspicious_url_words,second,10,updated keyword description\n",
        encoding="utf-8",
    )

    assert load_category_keywords("suspicious_url_words", [], keyword_path) == [
        "second"
    ]
