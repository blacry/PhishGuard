"""Optional, privacy-preserving OpenPhish community-feed lookups.

The public feed is downloaded; submitted URLs are never sent to the provider.
"""

import ipaddress
import json
import logging
import os
import tempfile
import time
from urllib.error import URLError
from urllib.parse import urlparse, urlunsplit
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

OPENPHISH_FEED_URL = (
    "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
)
FEED_SOURCE = "OpenPhish Community Feed"
REQUEST_TIMEOUT_SECONDS = 10
MAX_FEED_BYTES = 10 * 1024 * 1024
MAX_FEED_ENTRIES = 500_000
CACHE_TTL_SECONDS = 12 * 60 * 60
MIN_REFRESH_INTERVAL_SECONDS = 60 * 60

_memory_cache_path = None
_memory_cache_mtime = None
_memory_cache_state = None


def _cache_path():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, "..", "data", "openphish_cache.json")


def _normalize_host(value):
    host = value.strip().rstrip(".").lower()
    if not host:
        return None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = ascii_host.split(".")
    if len(ascii_host) > 253 or len(labels) < 2:
        return None
    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(char.isalnum() or char == "-" for char in label)
        ):
            return None
    if not (labels[-1].isalpha() or labels[-1].startswith("xn--")):
        return None
    return ascii_host


def _normalize_url(value):
    try:
        value = value.strip()
        if "://" not in value:
            value = "http://" + value
        parsed = urlparse(value)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or parsed.username or parsed.password:
            return None
        hostname = _normalize_host(parsed.hostname or "")
        port = parsed.port
    except (AttributeError, TypeError, ValueError):
        return None
    if not hostname:
        return None

    if ":" in hostname:
        hostname = f"[{hostname}]"
    default_port = (scheme == "http" and port == 80) or (
        scheme == "https" and port == 443
    )
    netloc = hostname if not port or default_port else f"{hostname}:{port}"
    return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))


def parse_openphish_feed(contents):
    """Parse one URL per line from the OpenPhish Community Feed."""
    urls = set()
    for line in contents.splitlines():
        normalized = _normalize_url(line)
        if normalized:
            urls.add(normalized)
        if len(urls) > MAX_FEED_ENTRIES:
            raise ValueError("OpenPhish feed exceeds the configured entry limit")
    return urls


def _empty_cache_state():
    return {"urls": set(), "fetched_at": 0.0, "last_attempt_at": 0.0}


def _read_cache_state():
    global _memory_cache_path, _memory_cache_mtime, _memory_cache_state
    path = _cache_path()
    try:
        mtime = os.path.getmtime(path)
    except FileNotFoundError:
        return _empty_cache_state()
    except OSError:
        logger.exception("Could not inspect OpenPhish cache file")
        return {"urls": set(), "fetched_at": 0.0, "last_attempt_at": time.time()}

    if path == _memory_cache_path and mtime == _memory_cache_mtime:
        return {
            "urls": set(_memory_cache_state["urls"]),
            "fetched_at": _memory_cache_state["fetched_at"],
            "last_attempt_at": _memory_cache_state["last_attempt_at"],
        }

    try:
        with open(path, "rb") as cache_file:
            encoded = cache_file.read(MAX_FEED_BYTES + 1)
        if len(encoded) > MAX_FEED_BYTES:
            raise ValueError("OpenPhish cache exceeds the configured size limit")
        payload = json.loads(encoded.decode("utf-8"))
        raw_urls = payload["urls"]
        if not isinstance(raw_urls, list) or len(raw_urls) > MAX_FEED_ENTRIES:
            raise ValueError("OpenPhish cache has an invalid URL list")
        urls = {
            normalized
            for value in raw_urls
            if isinstance(value, str)
            for normalized in [_normalize_url(value)]
            if normalized
        }
        state = {
            "urls": urls,
            "fetched_at": float(payload.get("fetched_at", 0)),
            "last_attempt_at": float(payload.get("last_attempt_at", 0)),
        }
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        logger.exception("Could not read OpenPhish cache; treating it as unavailable")
        state = _empty_cache_state()

    _memory_cache_path = path
    _memory_cache_mtime = mtime
    _memory_cache_state = state
    return {
        "urls": set(state["urls"]),
        "fetched_at": state["fetched_at"],
        "last_attempt_at": state["last_attempt_at"],
    }


def _write_cache_state(state):
    global _memory_cache_path, _memory_cache_mtime, _memory_cache_state
    path = _cache_path()
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=directory,
            prefix=".openphish-cache-",
            suffix=".tmp",
            delete=False,
        ) as cache_file:
            temporary_path = cache_file.name
            json.dump({
                "fetched_at": state["fetched_at"],
                "last_attempt_at": state["last_attempt_at"],
                "urls": sorted(state["urls"]),
            }, cache_file)
        os.replace(temporary_path, path)
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)

    _memory_cache_path = path
    _memory_cache_mtime = os.path.getmtime(path)
    _memory_cache_state = {
        "urls": set(state["urls"]),
        "fetched_at": state["fetched_at"],
        "last_attempt_at": state["last_attempt_at"],
    }


def _refresh_cache_if_due(state, now):
    if now - state["fetched_at"] < CACHE_TTL_SECONDS:
        return state, False, ""
    if now - state["last_attempt_at"] < MIN_REFRESH_INTERVAL_SECONDS:
        return state, False, "Feed refresh is rate-limited; using cached data if available."

    state["last_attempt_at"] = now
    try:
        _write_cache_state(state)
    except OSError:
        logger.exception("Could not persist OpenPhish refresh rate-limit state")
        return state, False, "Feed cache is not writable."

    request = Request(
        OPENPHISH_FEED_URL,
        headers={"User-Agent": "PhishGuard/1.0 community-feed updater"},
    )
    try:
        with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            status = getattr(response, "status", 200)
            if not isinstance(status, int) or not 200 <= status < 300:
                raise URLError(f"Unexpected feed HTTP status {status}")
            payload = response.read(MAX_FEED_BYTES + 1)
        if len(payload) > MAX_FEED_BYTES:
            raise ValueError("OpenPhish feed exceeds the configured size limit")
        urls = parse_openphish_feed(payload.decode("utf-8"))
        if not urls:
            raise ValueError("OpenPhish feed contained no usable entries")
        refreshed_state = {
            "urls": urls,
            "fetched_at": now,
            "last_attempt_at": now,
        }
        _write_cache_state(refreshed_state)
        return refreshed_state, True, ""
    except (OSError, UnicodeError, URLError, ValueError) as exc:
        logger.warning("OpenPhish feed refresh failed: %s", exc)
        return state, False, "Feed refresh failed; any cached result may be stale."


def lookup_url_reputation(url):
    """Return a feed status without transmitting the submitted URL."""
    enabled = os.environ.get("PHISHGUARD_ENABLE_OPENPHISH", "").strip().lower()
    if enabled not in {"1", "true", "yes", "on"}:
        return {
            "status": "disabled",
            "source": FEED_SOURCE,
            "detail": "Optional phishing-feed lookup is disabled; no network request was made.",
        }
    if not isinstance(url, str):
        return {
            "status": "unavailable",
            "source": FEED_SOURCE,
            "detail": "A URL string is required for the reputation lookup.",
        }

    normalized_url = _normalize_url(url)
    if not normalized_url:
        return {
            "status": "unavailable",
            "source": FEED_SOURCE,
            "detail": "Could not normalize the URL for the reputation lookup.",
        }

    now = time.time()
    try:
        state, refreshed, refresh_detail = _refresh_cache_if_due(
            _read_cache_state(), now
        )
    except OSError:
        logger.exception("OpenPhish cache operation failed")
        return {
            "status": "unavailable",
            "source": FEED_SOURCE,
            "detail": "Could not read or update the local phishing-feed cache.",
        }

    feed_is_fresh = bool(
        state["fetched_at"] and now - state["fetched_at"] < CACHE_TTL_SECONDS
    )
    if normalized_url in state["urls"] and feed_is_fresh:
        status = "known_malicious"
        detail = "Exact URL is listed in the OpenPhish phishing feed."
    elif normalized_url in state["urls"]:
        status = "unknown"
        detail = "A stale feed listed this URL, but its current status could not be confirmed."
    elif feed_is_fresh:
        status = "not_listed"
        detail = "Exact URL is not listed in the current OpenPhish feed."
    elif state["urls"]:
        status = "unknown"
        detail = "Exact URL was not found in a stale feed; this is not a clean verdict."
    else:
        status = "unavailable"
        detail = "No usable OpenPhish feed cache is available."

    if refresh_detail:
        detail = f"{detail} {refresh_detail}"
    elif refreshed:
        detail = f"{detail} Feed refreshed."
    return {"status": status, "source": FEED_SOURCE, "detail": detail}


def summarize_reputation_results(results):
    """Reduce URL lookups to a persisted status without merging heuristic scores."""
    if not results:
        return "not_checked", FEED_SOURCE
    statuses = {result.get("status") for result in results}
    if "known_malicious" in statuses:
        status = "known_malicious"
    elif "unavailable" in statuses:
        status = "unavailable"
    elif "unknown" in statuses:
        status = "unknown"
    elif "not_listed" in statuses:
        status = "not_listed"
    elif statuses == {"disabled"}:
        status = "disabled"
    else:
        status = "unavailable"
    return status, FEED_SOURCE
