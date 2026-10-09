import os
import sys
import tempfile

import streamlit as st

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parser.parser import parse_email_file
from fusion.fusion import analyze_email

st.set_page_config(page_title="Email Threat Detection", page_icon="📧")
st.write("hello, dashboard is running")
st.title("Email Threat Detection & Forensics")
st.write("Upload an .eml file to analyze it.")

uploaded = st.file_uploader("Upload .eml file", type=["eml"])

if uploaded:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
        tmp.write(uploaded.getvalue())
        path = tmp.name

    try:
        email = parse_email_file(path)
        report = analyze_email(email)
    finally:
        os.remove(path)

    level = report["risk_level"]
    colors = {"LOW": "green", "MEDIUM": "orange", "HIGH": "red"}

    st.markdown(f"## Risk: :{colors[level]}[{level}]")
    st.metric("Risk score", report["risk_score"])

    st.subheader("Email details")
    st.write(f"**Subject:** {email.subject}")
    st.write(f"**From:** {email.sender}")
    st.write(f"**Origin IP:** {email.origin_ip}")

    st.subheader("Engine results")
    for r in report["engine_results"]:
        with st.expander(f"{r.engine_name}: {r.verdict} ({r.score})", expanded=True):
            for e in r.evidence:
                st.write("- " + e)

    lines = [
        f"Risk: {level} ({report['risk_score']})",
        f"Subject: {email.subject}",
        f"From: {email.sender}",
        f"Origin IP: {email.origin_ip}",
        "",
    ]
    for r in report["engine_results"]:
        lines.append(f"[{r.engine_name}] {r.verdict} ({r.score})")
        lines += [f"  - {e}" for e in r.evidence]

    st.download_button(
        "Download forensic report",
        "\n".join(lines),
        file_name="forensic_report.txt",
    )