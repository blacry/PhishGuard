import tempfile
import unittest
import zipfile
from pathlib import Path

from database.urlhaus_database import check_url, load_database, normalize_url


CSV_FIXTURE = """################################################################
# URLhaus test fixture
# Last updated: 2026-11-27 17:17:12 (UTC)
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
1001,2026-11-27 10:00:00,http://bad.example/drop.exe,online,2026-11-27 10:00:00,malware_download,None,https://urlhaus.abuse.ch/url/1001/,tester
1002,2026-11-27 10:05:00,https://other.example/a?x=1,offline,2026-11-27 10:05:00,malware_download,None,https://urlhaus.abuse.ch/url/1002/,tester
"""


class UrlhausDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.archive_path = Path(self.temporary_directory.name) / "fixture.zip"
        with zipfile.ZipFile(self.archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("csv.txt", CSV_FIXTURE)
        self.database = load_database(self.archive_path)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_normalization_ignores_scheme_and_fragment(self):
        self.assertEqual(
            normalize_url("http://Bad.Example/drop.exe#part"),
            normalize_url("https://bad.example/drop.exe"),
        )

    def test_invalid_scheme_is_rejected(self):
        self.assertIsNone(normalize_url("ftp://bad.example/file"))
        self.assertIsNone(normalize_url("not a url"))

    def test_loader_reads_csv_comments_and_records(self):
        self.assertTrue(self.database["ok"])
        self.assertEqual(self.database["count"], 2)
        self.assertEqual(self.database["updated"], "2026-11-27 17:17:12 (UTC)")

    def test_exact_match_is_malware(self):
        result = check_url("https://bad.example/drop.exe", self.database)
        self.assertEqual(result["status"], "malware")
        self.assertEqual(result["record"]["id"], "1001")

    def test_same_host_different_path_is_related(self):
        result = check_url("https://bad.example/other.exe", self.database)
        self.assertEqual(result["status"], "related_host")
        self.assertEqual(result["related"][0]["id"], "1001")

    def test_missing_url_is_not_listed(self):
        result = check_url("https://clean.example/", self.database)
        self.assertEqual(result["status"], "not_listed")

    def test_invalid_input_is_rejected(self):
        self.assertEqual(check_url("", self.database)["status"], "invalid")

    def test_missing_or_invalid_archive_is_reported(self):
        missing = load_database(Path(self.temporary_directory.name) / "missing.zip")
        self.assertFalse(missing["ok"])

        invalid_path = Path(self.temporary_directory.name) / "invalid.zip"
        invalid_path.write_text("not a zip", encoding="utf-8")
        invalid = load_database(invalid_path)
        self.assertFalse(invalid["ok"])

    def test_supplied_database_can_match_one_of_its_own_records(self):
        full_database = load_database()
        self.assertTrue(full_database["ok"], full_database.get("error"))
        sample_record = next(iter(full_database["by_url"].values()))
        self.assertEqual(check_url(sample_record["url"], full_database)["status"], "malware")


if __name__ == "__main__":
    unittest.main()
