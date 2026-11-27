"""Small Streamlit interface for checking URLs against the local URLhaus dump."""

import streamlit as st

from database.urlhaus_database import DATABASE_FILE, check_url, load_database

st.set_page_config(page_title="PhishGuard URL Check", page_icon="🛡️", layout="centered")


@st.cache_resource(show_spinner="Loading the local malware URL database…")
def get_database():
    return load_database()


st.title("🛡️ PhishGuard URL Check")
st.write("Check whether a URL appears in the local URLhaus malware URL database.")
st.caption("The checker does not open the URL or send it to an online service.")

database = get_database()
if database["ok"]:
    st.caption(f"Database: {database['count']:,} unique URLs · last updated {database['updated']}")
else:
    st.error(database["error"])

with st.form("url_check"):
    submitted_url = st.text_input("URL to check", placeholder="https://example.com/path")
    submitted = st.form_submit_button("Check URL", type="primary")

if submitted:
    result = check_url(submitted_url, database)

    if result["status"] == "invalid":
        st.error(result["error"])
    elif result["status"] == "database_error":
        st.error(result["error"])
    elif result["status"] == "malware":
        st.error("MALWARE — exact URL match in the URLhaus database")
        record = result["record"]
        st.write(f"**Threat:** {record.get('threat') or 'Unknown'}")
        st.write(f"**URL status in database:** {record.get('url_status') or 'Unknown'}")
        st.write(f"**First reported:** {record.get('dateadded') or 'Unknown'}")
        st.write(f"**URLhaus record ID:** {record.get('id') or 'Unknown'}")
    elif result["status"] == "related_host":
        st.warning("POTENTIALLY MALICIOUS — this host has malware URLs in the database, but the submitted URL is not an exact match.")
        st.write(f"Related database records: {len(result['related'])} shown (up to 5).")
        for record in result["related"]:
            st.code(record.get("url", ""), language=None)
            st.caption(f"Threat: {record.get('threat') or 'Unknown'} · Status: {record.get('url_status') or 'Unknown'} · ID: {record.get('id') or 'Unknown'}")
    else:
        st.info("NOT LISTED — no exact URL or matching host was found in this database. It might be safe, but this database match alone cannot confirm that.")

    st.caption("A database match is evidence that the URL was reported to URLhaus. A URL that is not listed might be safe, but it could also be new or missing from this snapshot.")

with st.expander("About this database"):
    st.write("This app uses the URLhaus CSV dump supplied with the project. URLhaus collects URLs associated with malware distribution.")
    st.write(f"Local file: `{DATABASE_FILE.relative_to(DATABASE_FILE.parents[1])}`")
    st.caption("The database is a snapshot and may become stale. This app only checks records present in that local file.")
