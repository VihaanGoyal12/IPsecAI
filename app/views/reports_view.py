"""
IPsecAI - Reports & Export View
Provides Technical & Executive report generation with instant export to HTML, JSON, CSV, and Markdown.
Includes sample dataset download, research citations, and prototype limitations.
"""

import streamlit as st
import pandas as pd
from backend.models.schema import AnalysisResult
from backend.reporting.report_generator import ReportGenerator
from backend.ml.dataset_generator import generate_synthetic_flow_dataset

report_gen = ReportGenerator()


def render_reports(analysis: AnalysisResult):
    st.markdown("""
    <div class="main-header">
        <h1 class="main-title">Security Reports & Compliance Audit</h1>
        <div class="main-subtitle">
            Generate formal technical audit reports, executive risk briefings, and structured dataset exports.
        </div>
    </div>
    """, unsafe_allow_html=True)

    c1, c2 = st.columns(2)
    with c1:
        report_type = st.radio("Report Type", ["Technical Assessment Report", "Executive Summary Briefing"], horizontal=True)

    with c2:
        st.caption(f"Active Report Session: `{analysis.analysis_id}` | Score: `{analysis.security_assessment.overall_score}/100`")

    # Generate documents
    if report_type == "Technical Assessment Report":
        md_content = report_gen.generate_technical_report_markdown(analysis)
        html_content = report_gen.generate_html_report(analysis)
    else:
        md_content = report_gen.generate_executive_summary_markdown(analysis)
        html_content = f"<html><body><pre>{md_content}</pre></body></html>"

    json_content = report_gen.generate_json_export(analysis)
    csv_content = report_gen.generate_findings_csv(analysis)

    # Export Download Buttons
    st.markdown("### Export Artifacts")
    d1, d2, d3, d4 = st.columns(4)
    with d1:
        st.download_button(
            "Download HTML Report",
            data=html_content,
            file_name=f"ipsecai_report_{analysis.analysis_id.lower()}.html",
            mime="text/html",
            use_container_width=True
        )
    with d2:
        st.download_button(
            "Download Markdown",
            data=md_content,
            file_name=f"ipsecai_report_{analysis.analysis_id.lower()}.md",
            mime="text/markdown",
            use_container_width=True
        )
    with d3:
        st.download_button(
            "Download JSON State",
            data=json_content,
            file_name=f"ipsecai_state_{analysis.analysis_id.lower()}.json",
            mime="application/json",
            use_container_width=True
        )
    with d4:
        st.download_button(
            "Download Findings CSV",
            data=csv_content,
            file_name=f"ipsecai_findings_{analysis.analysis_id.lower()}.csv",
            mime="text/csv",
            use_container_width=True
        )

    st.markdown("---")

    # Live Report Preview
    st.markdown("### Report Document Preview")
    st.markdown(md_content)

    st.markdown("---")

    # Sample Dataset Section
    st.markdown("### Research Dataset & Flow Statistics")
    st.caption("Observable flow statistical features used for training and evaluating prototype traffic classification models.")
    df_sample = generate_synthetic_flow_dataset(samples_per_class=10)
    st.dataframe(df_sample, hide_index=True, use_container_width=True)

    csv_dataset = df_sample.to_csv(index=False)
    st.download_button(
        "Download Sample Flow Dataset (CSV)",
        data=csv_dataset,
        file_name="ipsecai_sample_flow_dataset.csv",
        mime="text/csv"
    )

    # Prototype Limitations & Research Grounding
    st.markdown("---")
    st.markdown("### Prototype Limitations & Scientific Context")
    st.markdown("""
    - **Defensive & Observable Metadata Focus**: In accordance with cryptographic standards, payload contents are not inspected or decrypted. Inferences rely solely on flow metadata (packet lengths, inter-arrival time distributions, burst clustering, directional volume ratios).
    - **Heuristic Scoring Model**: The security score (0-100) represents a prototype heuristic calculation grounded in NIST SP 800-77 Rev. 1 guidelines, not an official NTRO certification formula.
    - **Zero-Friction Fallback**: When low-level packet capture binaries (TShark / Zeek) or external streaming clusters (Kafka) are absent, the application gracefully provides realistic synthetic demo profiles.

    **Research References Grounding this Framework**:
    1. **NIST SP 800-77 Rev. 1**: *Guide to IPsec VPNs*, National Institute of Standards and Technology. [https://csrc.nist.gov/pubs/sp/800/77/r1/final](https://csrc.nist.gov/pubs/sp/800/77/r1/final)
    2. **Fesl & Naas (2025)**: *A comprehensive machine learning-based approach for virtual private network traffic detection, classification and hiding*, Computer Networks. DOI: [10.1016/j.comnet.2025.111530](https://doi.org/10.1016/j.comnet.2025.111530)
    3. **Luo, Chu & Yang (2023)**: *IP packet-level encrypted traffic classification using machine learning with a light weight feature engineering method*, Journal of Information Security and Applications. DOI: [10.1016/j.jisa.2023.103519](https://doi.org/10.1016/j.jisa.2023.103519)
    4. **Roy, Shapira & Shavitt (2022)**: *Fast and lean encrypted Internet traffic classification*, Computer Communications. DOI: [10.1016/j.comcom.2022.02.003](https://doi.org/10.1016/j.comcom.2022.02.003)
    """)
