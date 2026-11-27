"""Create a downloadable PDF report with ReportLab."""

from datetime import datetime
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from xml.sax.saxutils import escape


def generate_pdf(category, summary, result, recommendations, urls=None, virustotal=None):
    output = BytesIO()
    document = SimpleDocTemplate(output, pagesize=letter, rightMargin=48, leftMargin=48, topMargin=48, bottomMargin=48)
    styles = getSampleStyleSheet()
    story = [Paragraph("PhishGuard", styles["Title"]), Paragraph("Detect. Analyse. Protect.", styles["Normal"]), Spacer(1, 12)]
    story.append(Paragraph("Security Analysis Report", styles["Heading1"]))
    story.append(Paragraph("Generated: " + datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z"), styles["Normal"]))
    story.append(Paragraph("Category: " + escape(category.title()), styles["Normal"]))
    story.append(Paragraph("Summary: " + escape((summary or "")[:240]), styles["Normal"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Overall assessment", styles["Heading2"]))
    story.append(Paragraph("Risk score: " + str(result["score"]) + "/100 — " + escape(result["classification"]), styles["Normal"]))
    story.append(Paragraph("This score is a heuristic estimate, not a probability of phishing.", styles["Normal"]))
    findings = result.get("findings", [])
    if findings:
        story.append(Paragraph("Detected indicators", styles["Heading2"]))
        rows = [["Indicator", "Points / Severity", "Explanation"]]
        for item in findings:
            rows.append([Paragraph(escape(item.get("indicator", "")), styles["BodyText"]), Paragraph(str(item.get("points", 0)) + " / " + escape(item.get("severity", "")), styles["BodyText"]), Paragraph(escape(item.get("explanation", "")), styles["BodyText"]),])
        table = Table(rows, colWidths=[120, 85, 270], repeatRows=1)
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D9488")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F1F5F9")]), ("PADDING", (0, 0), (-1, -1), 6)]))
        story.append(table)
    if urls:
        story.append(Paragraph("Extracted URLs", styles["Heading2"]))
        story.extend(Paragraph(escape(url), styles["BodyText"]) for url in urls)
    if virustotal:
        story.append(Paragraph("VirusTotal", styles["Heading2"]))
        story.append(Paragraph(escape(virustotal.get("message", "")), styles["BodyText"]))
        if virustotal.get("available"):
            story.append(Paragraph("Malicious: {malicious} | Suspicious: {suspicious} | Harmless: {harmless} | Undetected: {undetected}".format(**virustotal), styles["BodyText"]))
    story.append(Paragraph("Recommended actions", styles["Heading2"]))
    story.extend(Paragraph("• " + escape(item), styles["BodyText"]) for item in recommendations)
    story.append(Spacer(1, 10))
    story.append(Paragraph("Disclaimer: PhishGuard uses local rules and optional third-party reputation data. It cannot guarantee that a link or message is safe or malicious.", styles["Italic"]))
    document.build(story)
    return output.getvalue()
