import pytest


@pytest.fixture(autouse=True)
def isolate_scan_storage(tmp_path, monkeypatch):
    from utils import helpers

    monkeypatch.setattr(helpers, "_get_database_path", lambda: str(tmp_path / "history.sqlite3"))
