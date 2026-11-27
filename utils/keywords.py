"""Shared loading and validation for the phishing keyword CSV."""

import csv
import logging
import os

logger = logging.getLogger(__name__)
KEYWORD_CATEGORIES = {
    "urgency",
    "threat",
    "credential",
    "financial",
    "reward",
    "suspicious_url_words",
}
KEYWORD_FIELDS = ["category", "keyword", "weight", "description"]


def _default_keyword_path():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, "..", "data", "keywords.csv")


def _read_keyword_file(path):
    rows = []
    issues = []
    seen = set()

    try:
        with open(path, mode="r", newline="", encoding="utf-8") as keyword_file:
            reader = csv.DictReader(keyword_file, strict=True)
            if reader.fieldnames != KEYWORD_FIELDS:
                return [], [
                    "Header must be exactly: " + ", ".join(KEYWORD_FIELDS)
                ]

            for line_number, row in enumerate(reader, start=2):
                if None in row:
                    issues.append(f"Line {line_number}: unexpected extra column")
                    continue

                category = (row.get("category") or "").strip().lower()
                keyword = (row.get("keyword") or "").strip().lower()
                weight_text = (row.get("weight") or "").strip()
                description = (row.get("description") or "").strip()
                if category not in KEYWORD_CATEGORIES:
                    issues.append(f"Line {line_number}: unknown category {category!r}")
                if not keyword:
                    issues.append(f"Line {line_number}: keyword is empty")
                if not description:
                    issues.append(f"Line {line_number}: description is empty")

                key = (category, keyword)
                if key in seen:
                    issues.append(
                        f"Line {line_number}: duplicate keyword {keyword!r} in {category!r}"
                    )
                seen.add(key)

                try:
                    weight = int(weight_text)
                    if not 1 <= weight <= 100:
                        raise ValueError
                except ValueError:
                    issues.append(
                        f"Line {line_number}: weight must be an integer from 1 to 100"
                    )
                    continue

                rows.append({
                    "category": category,
                    "keyword": keyword,
                    "weight": weight,
                    "description": description,
                })
    except csv.Error as exc:
        issues.append(f"CSV parsing error: {exc}")

    if not rows:
        issues.append("File contains no keyword rows")
    return rows, issues


def validate_keyword_file(path=None):
    """Return all schema and row issues found in a keyword CSV."""
    keyword_path = path or _default_keyword_path()
    try:
        _, issues = _read_keyword_file(keyword_path)
    except OSError as exc:
        return [f"Could not read keyword file: {exc}"]
    return issues


def load_category_keywords(category, default_list, path=None):
    """Load one validated category, warning and using defaults only if absent."""
    keyword_path = path or _default_keyword_path()
    try:
        rows, issues = _read_keyword_file(keyword_path)
    except FileNotFoundError:
        logger.warning("Keyword file missing at %s; using built-in defaults", keyword_path)
        return list(default_list)
    except OSError:
        logger.exception("Could not read keyword file at %s", keyword_path)
        raise

    if issues:
        raise ValueError(
            f"Invalid keyword file {keyword_path}: " + "; ".join(issues)
        )

    keywords = [row["keyword"] for row in rows if row["category"] == category]
    if not keywords:
        raise ValueError(f"Keyword file has no entries for category {category!r}")
    return keywords
