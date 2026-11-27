from urllib.parse import urlparse

from scanners import reputation


class FakeResponse:
    status = 200

    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self, size):
        return self.payload[:size]


def test_feed_parser_normalizes_exact_urls_and_ignores_invalid_lines():
    urls = reputation.parse_openphish_feed(
        "# comment\nHTTPS://bad.example/private/path#fragment\n"
        "ftp://bad.example/file\nnot a URL\nhttps://user:pass@example.com/login\n"
    )
    assert urls == {"https://bad.example/private/path"}
    assert reputation._normalize_url("bad.example/private/path") == (
        "http://bad.example/private/path"
    )


def test_lookup_downloads_feed_not_submitted_url_and_caches(monkeypatch, tmp_path):
    cache_path = tmp_path / "openphish_cache.json"
    requests = []
    monkeypatch.setattr(reputation, "_cache_path", lambda: str(cache_path))
    monkeypatch.setenv("PHISHGUARD_ENABLE_OPENPHISH", "true")

    def fake_urlopen(request, timeout):
        requests.append((request, timeout))
        return FakeResponse(b"https://bad.example/private/path\n")

    monkeypatch.setattr(reputation, "urlopen", fake_urlopen)
    listed = reputation.lookup_url_reputation("https://bad.example/private/path")
    not_listed = reputation.lookup_url_reputation("https://safe.example")
    different_path = reputation.lookup_url_reputation("https://bad.example/other")

    assert listed["status"] == "known_malicious"
    assert not_listed["status"] == "not_listed"
    assert different_path["status"] == "not_listed"
    assert len(requests) == 1
    assert requests[0][0].full_url == reputation.OPENPHISH_FEED_URL
    assert "bad.example" not in urlparse(requests[0][0].full_url).netloc
    assert requests[0][0].data is None
    assert requests[0][1] == reputation.REQUEST_TIMEOUT_SECONDS


def test_disabled_and_failed_feed_do_not_produce_clean_verdict(monkeypatch, tmp_path):
    monkeypatch.setattr(reputation, "_cache_path", lambda: str(tmp_path / "cache.json"))
    monkeypatch.delenv("PHISHGUARD_ENABLE_OPENPHISH", raising=False)
    assert reputation.lookup_url_reputation("https://example.com")["status"] == "disabled"

    monkeypatch.setenv("PHISHGUARD_ENABLE_OPENPHISH", "1")

    def timeout(*args, **kwargs):
        raise TimeoutError("test timeout")

    monkeypatch.setattr(reputation, "urlopen", timeout)
    result = reputation.lookup_url_reputation("https://example.com")
    assert result["status"] == "unavailable"
    assert "not a clean verdict" not in result["detail"]


def test_stale_feed_never_returns_not_listed(monkeypatch, tmp_path):
    cache_path = tmp_path / "openphish_cache.json"
    cache_path.write_text(
        '{"fetched_at":1,"last_attempt_at":1,"urls":["https://listed.example/"]}',
        encoding="utf-8",
    )
    monkeypatch.setattr(reputation, "_cache_path", lambda: str(cache_path))
    monkeypatch.setenv("PHISHGUARD_ENABLE_OPENPHISH", "1")
    monkeypatch.setattr(
        reputation, "urlopen", lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError())
    )

    result = reputation.lookup_url_reputation("https://unlisted.example")
    listed_result = reputation.lookup_url_reputation("https://listed.example/")
    assert result["status"] == "unknown"
    assert listed_result["status"] == "unknown"
