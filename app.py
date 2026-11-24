"""Streamlit web interface for PhishGuard."""

import json

import pandas as pd
import streamlit as st

from scanner import scan_message, scan_url
from storage import add_scan, clear_history, get_history, get_stats
from utils.validators import is_valid_url


st.set_page_config(page_title="PhishGuard", page_icon="🛡️", layout="wide")
st.markdown(
    """
    <style>
        :root {
            --text-color: #f3f0e6;
            --background-color: #090a08;
            --secondary-background-color: #15160f;
            --primary-color: #e2ad2a;
        }
        .stApp {
            background: #090a08;
            color: #f3f0e6;
            color-scheme: dark;
        }
        [data-testid="stHeader"] {
            background: #090a08;
        }
        [data-testid="stMainBlockContainer"] {
            max-width: 1240px;
            padding-top: 1.1rem;
            padding-bottom: 3rem;
        }
        [data-testid="stMain"] {
            color: #f3f0e6;
        }
        [data-testid="stMain"] [data-testid="stMarkdownContainer"] {
            color: #e8e4d8;
        }
        [data-testid="stWidgetLabel"],
        [data-testid="stWidgetLabel"] p,
        [data-testid="stMarkdownContainer"] label {
            color: #ddd8c9 !important;
        }
        [data-testid="stCaptionContainer"] {
            color: #b7b2a3 !important;
        }
        [data-testid="stSidebar"] {
            background: #11120d;
            border-right: 1px solid #28271d;
        }
        [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] {
            color: #f3f0e6;
        }
        [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
            color: #b7b2a3;
        }
        [data-testid="stSidebar"] [role="radiogroup"] label {
            background: transparent;
            border: 1px solid transparent;
            border-radius: 7px;
            color: #e6e1d3 !important;
            padding: 0.6rem 0.75rem;
            margin: 0.25rem 0;
            transition: border-color 150ms ease, background 150ms ease;
        }
        [data-testid="stSidebar"] [role="radiogroup"] label p {
            color: inherit !important;
        }
        [data-testid="stSidebar"] [role="radiogroup"] label:hover {
            background: #1b1b12;
            border-color: #51451f;
        }
        [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {
            background: #282311;
            border-color: #9c7920;
            color: #ffda69 !important;
        }
        .sidebar-brand {
            border-bottom: 1px solid #302d20;
            margin-bottom: 1.2rem;
            padding: 0.8rem 0 1.3rem;
        }
        .sidebar-brand-name {
            color: #ffffff;
            font-size: 1.15rem;
            font-weight: 750;
            letter-spacing: 0.025em;
        }
        .sidebar-brand-copy {
            color: #b7b2a3;
            font-size: 0.84rem;
            margin-top: 0.35rem;
        }
        .hero {
            background:
                radial-gradient(ellipse at 50% 112%, rgba(201, 111, 14, 0.35), transparent 43%),
                radial-gradient(ellipse at 50% 120%, rgba(242, 174, 45, 0.16), transparent 58%),
                #050605;
            border: 1px solid #25251d;
            border-radius: 12px;
            color: #ffffff;
            isolation: isolate;
            margin-bottom: 2rem;
            overflow: hidden;
            padding: 3rem 1.5rem 2.6rem;
            position: relative;
            text-align: center;
        }
        .hero::after {
            border: 1px solid rgba(238, 164, 40, 0.4);
            border-radius: 50%;
            box-shadow: 0 -12px 58px rgba(226, 130, 23, 0.26);
            content: "";
            height: 210px;
            left: 16%;
            position: absolute;
            top: calc(100% - 78px);
            width: 68%;
            z-index: -1;
        }
        .hero-kicker {
            background: rgba(26, 27, 21, 0.9);
            border: 1px solid #343328;
            border-radius: 999px;
            color: #f1d27b;
            display: inline-block;
            font-size: 0.74rem;
            font-weight: 650;
            letter-spacing: 0.04em;
            padding: 0.48rem 0.9rem;
        }
        .hero h1 {
            color: #ffffff;
            font-size: clamp(2.35rem, 5.3vw, 4.4rem);
            letter-spacing: -0.045em;
            line-height: 1.04;
            margin: 1.2rem auto 0.8rem;
            max-width: 950px;
        }
        .hero p {
            color: #d3d0c6;
            font-size: 1.02rem;
            line-height: 1.55;
            margin: 0 auto;
            max-width: 660px;
        }
        .hero-pill {
            background: #f3f1e9;
            border-radius: 999px;
            color: #17170f;
            display: inline-block;
            font-size: 0.78rem;
            font-weight: 700;
            margin-top: 1.35rem;
            padding: 0.7rem 1.4rem;
        }
        .section-heading {
            margin: 0.2rem 0 1.2rem;
        }
        .section-kicker {
            color: #edbd43;
            font-size: 0.75rem;
            font-weight: 750;
            letter-spacing: 0.06em;
        }
        .section-heading h2 {
            color: #f5f1e7;
            font-size: 1.75rem;
            letter-spacing: -0.025em;
            margin: 0.25rem 0;
        }
        .section-heading p {
            color: #b7b2a3;
            margin: 0;
        }
        [data-testid="stVerticalBlockBorderWrapper"] {
            background: #14150f;
            border-color: #302f24;
            border-radius: 10px;
        }
        [data-testid="stMetric"] {
            background: #1a1b13;
            border: 1px solid #353326;
            border-radius: 8px;
            padding: 0.9rem 1.05rem;
        }
        [data-testid="stMetricLabel"] {
            color: #c6c1b2 !important;
            font-weight: 650;
        }
        [data-testid="stMetricValue"] {
            color: #fffdf6;
            font-weight: 750;
        }
        [data-testid="stProgressBar"] > div {
            background: #302c1c;
        }
        [data-testid="stProgressBar"] > div > div {
            background: #e2ad2a;
        }
        [data-testid="stTextInput"] input,
        [data-testid="stTextArea"] textarea {
            background: #1a1b14;
            border: 1px solid #514d3a;
            border-radius: 7px;
            color: #f4f1e8 !important;
            caret-color: #e2ad2a;
        }
        [data-testid="stTextInput"] input::placeholder,
        [data-testid="stTextArea"] textarea::placeholder {
            color: #aaa597;
            opacity: 1;
        }
        [data-testid="stTextInput"] input:focus,
        [data-testid="stTextArea"] textarea:focus {
            border-color: #d4a52e;
            box-shadow: 0 0 0 2px rgba(226, 173, 42, 0.18);
        }
        [data-testid="stBaseButton-primary"] {
            background: #e2ad2a;
            border: 1px solid #e2ad2a;
            border-radius: 999px;
            color: #17150e;
            font-weight: 750;
            min-height: 2.7rem;
        }
        [data-testid="stBaseButton-primary"]:hover {
            background: #f0c34e;
            border-color: #f0c34e;
            color: #17150e;
        }
        [data-testid="stBaseButton-secondary"] {
            background: #1b1c15;
            border: 1px solid #4d4937;
            border-radius: 999px;
            color: #eee9dc;
        }
        [data-testid="stExpander"] {
            background: #191a13;
            border: 1px solid #353326;
            border-radius: 8px;
        }
        [data-testid="stAlert"] {
            border-radius: 8px;
        }
        [data-testid="stAlert"] p {
            color: #f3f0e6;
        }
        [data-testid="stDataFrame"] {
            background: #14150f;
            border: 1px solid #353326;
            border-radius: 8px;
        }
        .result-label {
            color: #edbd43;
            font-size: 0.75rem;
            font-weight: 750;
            letter-spacing: 0.06em;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

st.sidebar.markdown(
    """
    <div class="sidebar-brand">
        <div class="sidebar-brand-name">PHISHGUARD</div>
        <div class="sidebar-brand-copy">A smarter pause before you click.</div>
    </div>
    """,
    unsafe_allow_html=True,
)
st.sidebar.markdown("#### WORKSPACE")
page = st.sidebar.radio(
    "Navigation",
    ["Scan a URL", "Scan a message", "Scan history", "Statistics"],
    label_visibility="collapsed",
)
st.sidebar.markdown("---")
st.sidebar.caption("STATIC ANALYSIS · YOUR LINKS ARE NEVER OPENED")

st.markdown(
    """
    <div class="hero">
        <div class="hero-kicker">PHISHGUARD &nbsp;·&nbsp; PRIVATE RISK CHECK</div>
        <h1>Know before you click.</h1>
        <p>Check links and messages for phishing signals, without ever opening the link.</p>
        <span class="hero-pill">PRIVATE BY DESIGN · STATIC ANALYSIS ONLY</span>
    </div>
    """,
    unsafe_allow_html=True,
)


def render_heading(kicker, title, caption):
    st.markdown(
        f"""
        <div class="section-heading">
            <div class="section-kicker">{kicker}</div>
            <h2>{title}</h2>
            <p>{caption}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_result(result):
    score, level, indicators = (
        result["score"],
        result["level"],
        result["indicators"],
    )
    with st.container(border=True, key=f"result-panel-{level.lower()}"):
        st.markdown('<div class="result-label">SCAN COMPLETE</div>', unsafe_allow_html=True)
        score_card, level_card, indicator_card = st.columns(3)
        score_card.metric("Risk score", f"{score} / 100")
        level_card.metric("Threat level", level)
        indicator_card.metric("Indicators count", len(indicators))
        st.progress(score / 100)

        message = f"Threat level: {level}."
        if level == "LOW":
            st.success(message, icon="✅")
        elif level == "MEDIUM":
            st.warning(message, icon="⚠️")
        else:
            st.error(message, icon="🚨")

        with st.expander("Indicator breakdown", expanded=bool(indicators)):
            if indicators:
                for index, indicator in enumerate(indicators):
                    with st.container(border=True, key=f"indicator-{index}"):
                        st.write(f"🔎 {indicator}")
            else:
                st.write("✨ No phishing indicators detected.")


def render_latest_result(scan_type):
    latest = st.session_state.get("latest_scan")
    if latest and latest["type"] == scan_type:
        render_result(latest["result"])


def run_scan(scan_type, scan_input, scan_function):
    try:
        result = scan_function(scan_input)
    except ValueError as error:
        st.error(str(error))
        return

    st.session_state["latest_scan"] = {
        "type": scan_type,
        "input": scan_input,
        "result": result,
    }
    try:
        add_scan(scan_type, scan_input, result["score"], result["level"])
    except (OSError, json.JSONDecodeError, ValueError) as error:
        st.error(f"Scan completed, but could not save it to history: {error}")


if page == "Scan a URL":
    render_heading(
        "QUICK SCAN",
        "Scan a URL",
        "Inspect a link's structure without visiting or contacting the website.",
    )
    with st.container(border=True, key="url-scan-form"):
        url = st.text_input(
            "URL to inspect",
            placeholder="https://example.com/account",
        )
        if st.button("Scan URL", type="primary", width="stretch"):
            if not url.strip():
                st.info("Enter a URL to scan.")
            elif not is_valid_url(url):
                st.error("That URL does not look valid. Try a full address such as https://example.com.")
            else:
                run_scan("URL", url.strip(), scan_url)
    render_latest_result("URL")

elif page == "Scan a message":
    render_heading(
        "MESSAGE CHECK",
        "Scan a message",
        "Look for pressure tactics, credential requests, financial requests, and embedded links.",
    )
    with st.container(border=True, key="message-scan-form"):
        message = st.text_area(
            "Message to inspect",
            placeholder="Paste the email, text, or chat message here...",
            height=180,
        )
        if st.button("Scan message", type="primary", width="stretch"):
            if not message.strip():
                st.info("Enter a message to scan.")
            else:
                run_scan("Message", message.strip(), scan_message)
    render_latest_result("Message")

elif page == "Scan history":
    render_heading(
        "YOUR ACTIVITY",
        "Scan history",
        "Review your recent URL and message checks. Newest scans appear first.",
    )
    try:
        history = get_history()
    except (OSError, json.JSONDecodeError, ValueError) as error:
        st.error(f"Could not load scan history: {error}")
        history = []
    if history:
        history = sorted(history, key=lambda record: record.get("timestamp", ""), reverse=True)
        header, action = st.columns([5, 1])
        header.caption(f"{len(history)} saved scan(s)")
        if action.button("Clear history", type="secondary", width="stretch"):
            try:
                clear_history()
                st.rerun()
            except OSError as error:
                st.error(f"Could not clear scan history: {error}")
        st.dataframe(pd.DataFrame(history), width="stretch", hide_index=True)
    else:
        st.info("No scans yet. Your completed scans will show up here.")
        if st.button("Clear history", type="secondary"):
            try:
                clear_history()
                st.rerun()
            except OSError as error:
                st.error(f"Could not clear scan history: {error}")

elif page == "Statistics":
    render_heading(
        "AT A GLANCE",
        "Scan statistics",
        "A quick overview of the scans saved on this device.",
    )
    try:
        stats = get_stats()
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as error:
        st.error(f"Could not load scan statistics: {error}")
    else:
        high_risk_count = (
            stats["counts_per_level"]["HIGH"]
            + stats["counts_per_level"]["CRITICAL"]
        )
        total_card, high_card, average_card = st.columns(3)
        total_card.metric("Total scans", stats["total_scans"], help="All saved URL and message scans.")
        high_card.metric("High-risk scans", high_risk_count, help="Includes HIGH and CRITICAL results.")
        average_card.metric("Average score", f"{stats['average_score']} / 100")

        st.markdown("#### Threat level distribution")
        chart_data = pd.DataFrame.from_dict(
            stats["counts_per_level"], orient="index", columns=["Scans"]
        )
        chart_data.index.name = "Threat level"
        st.bar_chart(chart_data, color="#168a91")
