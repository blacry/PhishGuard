"""Optional VirusTotal lookup for URLs already present in its database."""

import base64
import os

import requests

API_BASE = "https://www.virustotal.com/api/v3"


def get_api_key(api_key=None):
    """Read a key passed directly, from the environment, or Streamlit secrets."""
    if api_key:
        return api_key
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if api_key:
        return api_key
    try:
        import streamlit as st

        return st.secrets.get("VIRUSTOTAL_API_KEY")
    except Exception:
        # Streamlit raises when no secrets file is configured; that is optional.
        return None


def is_configured():
    """Return whether either supported local key source has a key."""
    return bool(get_api_key())


def lookup_url(url, api_key=None, timeout=10):
    """Look up a URL identifier without submitting the URL or page contents."""
    api_key = get_api_key(api_key)
    if not api_key:
        return {"available": False, "message": "VirusTotal is not configured. Local analysis is still available."}
    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    try:
        response = requests.get(API_BASE + "/urls/" + url_id, headers={"x-apikey": api_key}, timeout=timeout)
        if response.status_code == 404:
            return {"available": False, "message": "VirusTotal has no existing report for this URL. It was not submitted."}
        if response.status_code == 429:
            return {"available": False, "message": "VirusTotal rate limit reached. Try again later."}
        response.raise_for_status()
        stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {"available": True, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "harmless": stats.get("harmless", 0), "undetected": stats.get("undetected", 0), "message": "Existing VirusTotal URL report retrieved."}
    except requests.RequestException:
        return {"available": False, "message": "Could not reach VirusTotal. Check the connection and try again."}
    except (ValueError, TypeError, AttributeError):
        return {"available": False, "message": "VirusTotal returned an unexpected response."}
