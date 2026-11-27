"""PhishGuard: a transparent, rule-based phishing analysis dashboard."""

from datetime import datetime

import pandas as pd
import streamlit as st

from core.recommendations import get_recommendations
from core.report_generator import generate_pdf
from core.risk_engine import score_findings
from database.history_manager import add_scan, clear_history, delete_scan, load_history
from detectors.email_detector import analyze_email
from detectors.message_detector import analyze_message
from detectors.url_detector import analyze_url
from services.qr_scanner import decode_qr
from services.virustotal import is_configured, lookup_url

st.set_page_config(page_title="PhishGuard", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.stApp {background:#0B1120;color:#F8FAFC} [data-testid="stSidebar"] {background:#111827}
[data-testid="stMetric"] {background:#111827;border:1px solid #263449;padding:16px;border-radius:14px}
.hero {padding:26px 30px;background:linear-gradient(120deg,#111827,#12343A);border:1px solid #24434B;border-radius:18px;margin-bottom:20px}
.hero h1 {margin:0;color:#F8FAFC}.hero p {color:#A7BEC7;margin:6px 0 0}
.small-muted {color:#A7B4C7;font-size:0.9rem}
</style>
""", unsafe_allow_html=True)

PAGES = ["Dashboard", "URL Scanner", "Email Scanner", "Message Scanner", "QR Code Scanner", "Scan History", "Security Awareness", "About PhishGuard"]


def show_result(category, summary, findings, urls=None, external=None):
    result = score_findings(findings)
    recommendations = get_recommendations(result["findings"], category)
    st.session_state["latest_report"] = {"category": category, "summary": summary, "result": result, "recommendations": recommendations, "urls": urls or [], "external": external}
    add_scan(category, summary, result)
    show_report(st.session_state["latest_report"])


def show_report(report):
    result = report["result"]
    score = result["score"]
    st.subheader("Analysis report")
    left, right = st.columns([1, 2])
    with left:
        st.metric("Risk score", f"{score} / 100", result["classification"])
        st.progress(score / 100)
        st.caption("A heuristic estimate, not a probability or guarantee.")
    with right:
        st.markdown("**Analysed:** " + report["category"].title())
        st.code(report["summary"][:300] or "No summary available", language=None)
    if result["findings"]:
        st.markdown("#### Warning indicators")
        for finding in result["findings"]:
            st.markdown(f"**{finding['severity']} · {finding['indicator']}** — +{finding['points']} points  \n{finding['explanation']}")
    else:
        st.success("No strong warning indicators were found by the local rules.")
    if report.get("urls"):
        st.markdown("#### Extracted URLs")
        for url in report["urls"]:
            st.code(url, language=None)
    external = report.get("external")
    if external:
        st.markdown("#### VirusTotal (external threat intelligence)")
        st.info(external["message"])
        if external.get("available"):
            cols = st.columns(4)
            for col, name in zip(cols, ["malicious", "suspicious", "harmless", "undetected"]):
                col.metric(name.title(), external.get(name, 0))
    st.markdown("#### Recommended actions")
    for advice in report["recommendations"]:
        st.markdown("- " + advice)
    try:
        pdf = generate_pdf(report["category"], report["summary"], result, report["recommendations"], report.get("urls"), external)
        st.download_button("Download PDF report", pdf, file_name="phishguard-report.pdf", mime="application/pdf")
    except Exception as error:
        st.warning("Could not create a PDF report: " + str(error))


st.sidebar.markdown("# 🛡️ PhishGuard")
st.sidebar.caption("Detect. Analyse. Protect.")
page = st.sidebar.radio("Navigate", PAGES, label_visibility="collapsed")
st.sidebar.markdown("---")
st.sidebar.caption("Local rule-based checks. Submitted URLs are never opened.")

if page == "Dashboard":
    st.markdown('<div class="hero"><h1>PhishGuard</h1><p>Understand suspicious links and messages before you interact with them.</p></div>', unsafe_allow_html=True)
    records = load_history()
    count = len(records)
    high_count = sum(record.get("score", 0) >= 61 for record in records)
    avg_score = round(sum(record.get("score", 0) for record in records) / count) if count else 0
    a, b, c = st.columns(3)
    a.metric("Scans recorded", count)
    b.metric("High or critical scans", high_count)
    c.metric("Average risk score", f"{avg_score}/100")
    st.markdown("### Start a scan")
    cols = st.columns(4)
    for col, title, target in zip(cols, ["URL", "Email", "Message", "QR code"], PAGES[1:5]):
        col.markdown(f"**{title} scanner**")
        col.caption("Inspect without opening links.")
    st.markdown("### Recent activity")
    if records:
        df = pd.DataFrame(records[:10])
        st.dataframe(df[["timestamp", "category", "summary", "score", "classification"]], use_container_width=True, hide_index=True)
        if count > 1:
            chart_data = pd.DataFrame({"Scan": range(1, min(count, 20) + 1), "Risk score": [item.get("score", 0) for item in records[:20]]}).set_index("Scan")
            st.line_chart(chart_data, color="#06B6D4")
    else:
        st.info("No scans yet. Choose a scanner from the sidebar to get started.")
    if st.session_state.get("latest_report"):
        show_report(st.session_state["latest_report"])

elif page == "URL Scanner":
    st.title("URL Scanner")
    st.caption("The scanner inspects the text of a URL only. It does not visit the destination.")
    if not is_configured():
        with st.expander("Set up optional VirusTotal lookups"):
            st.write("Get your personal API key from your VirusTotal account settings, then add it to `.streamlit/secrets.toml` or set `VIRUSTOTAL_API_KEY` in the terminal before starting Streamlit.")
            st.code('VIRUSTOTAL_API_KEY = "paste-your-key-here"', language="toml")
            st.caption("Keep this key private. After setting it, restart Streamlit and select the VirusTotal lookup checkbox. Local analysis works without a key.")
            st.markdown("[VirusTotal API key page](https://www.virustotal.com/gui/my-apikey)")
    with st.form("url_form"):
        url = st.text_input("URL", placeholder="https://example.com/account")
        check_vt = st.checkbox("Look up this URL in VirusTotal's existing database", help="This performs a reputation lookup. PhishGuard does not submit the URL or page content.")
        submitted = st.form_submit_button("Analyse URL", type="primary")
    if submitted:
        analysis = analyze_url(url)
        if not analysis["valid"]:
            st.error(analysis["error"])
        else:
            external = lookup_url(analysis["url"]) if check_vt else None
            if check_vt and not external.get("available"):
                st.caption(external["message"])
            with st.expander("Parsed URL details"):
                st.json(analysis["details"])
            show_result("url", analysis["details"]["full_url"], analysis["findings"], external=external)

elif page == "Email Scanner":
    st.title("Email Scanner")
    st.caption("Paste email text for local analysis. Do not include passwords, OTPs, or private information.")
    with st.form("email_form"):
        sender = st.text_input("Sender address (optional)", placeholder="name@example.com")
        body = st.text_area("Email content", height=230, placeholder="Paste the email text here…")
        submitted = st.form_submit_button("Analyse email", type="primary")
    if submitted:
        analysis = analyze_email(body, sender)
        if not analysis["valid"]:
            st.error(analysis["error"])
        else:
            show_result("email", body[:180], analysis["findings"], analysis["urls"])

elif page == "Message Scanner":
    st.title("Message Scanner")
    st.caption("Check SMS, WhatsApp, Telegram, and other unexpected messages.")
    with st.form("message_form"):
        message = st.text_area("Message", height=200, placeholder="Paste the suspicious message here…")
        submitted = st.form_submit_button("Analyse message", type="primary")
    if submitted:
        analysis = analyze_message(message)
        if not analysis["valid"]:
            st.error(analysis["error"])
        else:
            show_result("message", message[:180], analysis["findings"], analysis["urls"])

elif page == "QR Code Scanner":
    st.title("QR Code Scanner")
    st.caption("Upload a PNG or JPG image up to 5 MB. Decoded links are analysed but never opened.")
    uploaded = st.file_uploader("QR image", type=["png", "jpg", "jpeg"])
    if uploaded and st.button("Decode and analyse", type="primary"):
        decoded = decode_qr(uploaded)
        if not decoded["ok"]:
            st.error(decoded["error"])
        else:
            st.markdown("**Decoded text**")
            st.code(decoded["text"], language=None)
            analysis = analyze_url(decoded["text"])
            if analysis["valid"]:
                show_result("qr code", decoded["text"], analysis["findings"], [decoded["text"]])
            else:
                show_result("qr code", decoded["text"], [], [])
                st.info("The QR code contains text rather than a URL, so URL checks were not run.")

elif page == "Scan History":
    st.title("Scan History")
    records = load_history()
    if records:
        filter_type = st.selectbox("Scan type", ["All"] + sorted({item.get("category", "") for item in records}))
        filter_risk = st.selectbox("Risk level", ["All", "Low Risk", "Moderate Risk", "Suspicious", "High Risk", "Critical Risk"])
        shown = [item for item in records if (filter_type == "All" or item.get("category") == filter_type) and (filter_risk == "All" or item.get("classification") == filter_risk)]
        st.dataframe(pd.DataFrame(shown), use_container_width=True, hide_index=True)
        choices = {f"{item.get('timestamp', '')[:19]} · {item.get('category', '')} · {item.get('classification', '')} · {item.get('summary', '')[:45]}": item.get("id") for item in shown}
        selected = st.selectbox("Inspect or delete a scan", list(choices)) if choices else None
        if selected:
            record = next((item for item in shown if item.get("id") == choices[selected]), None)
            if record:
                st.json(record)
            if st.button("Delete selected scan"):
                delete_scan(choices[selected])
                st.rerun()
        if st.checkbox("I understand that clearing history is permanent") and st.button("Clear all history", type="secondary"):
            clear_history()
            st.rerun()
    else:
        st.info("No scan history is available yet.")

elif page == "Security Awareness":
    st.title("Security Awareness")
    lessons = [
        ("Inspect the real domain", "Read from the end of a hostname: support.example.com belongs to example.com. A brand name earlier in a URL does not make it official.", "Example: paypal.com.example.net is hosted under example.net."),
        ("Bank messages", "Banks do not need your password, PIN, CVV, or OTP over a message. Call the number printed on your card or use the official banking app.", "A threat that your account will close today is a reason to pause and verify."),
        ("Never share OTPs", "A one-time password is meant for you to enter into a service you intentionally opened. A person asking you to read it aloud is a warning sign.", "Do not share an OTP with callers, message senders, or supposed support staff."),
        ("Delivery notifications", "Unexpected delivery fees and address correction links can be used to steal card data. Check tracking through the courier's official app or site.", "Do not pay a small fee through a link in an unexpected SMS."),
        ("Email attachments", "Unexpected files can contain harmful content. Verify with the sender through another channel before opening, especially archives or executable files.", "A familiar display name does not prove who sent the email."),
        ("HTTPS is not a trust badge", "HTTPS encrypts the connection to a site; it does not verify the site's intentions. Scam sites can use HTTPS too.", "Check the domain and the reason the sender wants you to act."),
        ("Report and browse safely", "Use your email or messaging app's phishing report feature. Keep software updated, use bookmarks for important services, and avoid logging in from unsolicited links.", "If in doubt, navigate independently to the official service."),
    ]
    for title, detail, example in lessons:
        with st.expander(title, expanded=False):
            st.write(detail)
            st.info(example)

else:
    st.title("About PhishGuard")
    st.markdown("**PhishGuard — Detect. Analyse. Protect.**")
    st.write("A Python and Streamlit academic project that explains potential phishing indicators with simple, adjustable rules. It is designed to help users pause and verify, not to guarantee that any content is safe or malicious.")
    st.markdown("#### Privacy and limitations")
    st.write("URL checks run locally and never open the supplied address. Email and message content are summarized in local history rather than stored in full. VirusTotal is optional and performs a lookup only when selected; it does not submit new URLs. Detection is heuristic and may produce false positives or miss threats.")
    st.markdown("#### Technology")
    st.write("Python · Streamlit · Requests · Pandas · OpenCV · Pillow · ReportLab · JSON")
