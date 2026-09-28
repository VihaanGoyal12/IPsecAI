"""
IPsecAI - Overview View
Displays high-level analysis posture, score summary, findings table, and quick demo loading.
"""

import streamlit as st
import pandas as pd
from backend.models.schema import AnalysisResult


def render_overview(analysis: AnalysisResult, on_load_demo_callback):
    st.markdown("""
    <div class="main-header">
        <h1 class="main-title">IPsecAI</h1>
        <div style="font-weight: 600; color: #1e293b; font-size: 15px; margin-top: 2px;">
            AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
        </div>
        <div class="main-subtitle">
            Analyze IPsec VPN traffic, identify security parameters, and assess configuration risk.
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Actions Bar
    col1, col2, col3 = st.columns([2, 1.5, 2.5])
    with col1:
        demo_choice = st.selectbox(
            "Select Demo Capture Profile",
            options=["Demo A (Healthy Configuration)", "Demo B (Weak Configuration)", "Demo C (Encrypted Multi-Flow)"],
            index=0,
            label_visibility="collapsed"
        )
    with col2:
        if st.button("Load Demo Capture", type="primary", use_container_width=True):
            if "Demo A" in demo_choice:
                on_load_demo_callback("demo_a")
            elif "Demo B" in demo_choice:
                on_load_demo_callback("demo_b")
            else:
                on_load_demo_callback("demo_c")
            st.rerun()

    with col3:
        st.caption(f"Active Session: `{analysis.ipsec_session.session_id}` ({analysis.capture_summary.source_type})")

    if analysis.is_demo:
        st.markdown("""
        <div class="demo-banner">
            <strong>DEMO DATA:</strong> Simulated capture for prototype demonstration.
        </div>
        """, unsafe_allow_html=True)

    asm = analysis.security_assessment
    avg_conf = int(sum(c.confidence_score for c in analysis.traffic_classifications) / max(1, len(analysis.traffic_classifications)) * 100)

    # Horizontal Summary Bar
    st.markdown(f"""
    <div class="summary-bar">
        <div class="summary-metric">
            <div class="summary-label">Security Score</div>
            <div class="summary-value" style="color: {'#15803d' if asm.overall_score >= 80 else ('#b45309' if asm.overall_score >= 60 else '#b91c1c')};">
                {asm.overall_score} / 100
            </div>
        </div>
        <div class="summary-metric">
            <div class="summary-label">Risk Level</div>
            <div class="summary-value">
                <span class="{'badge-low' if asm.risk_level == 'Low' else ('badge-medium' if asm.risk_level == 'Medium' else 'badge-high')}">
                    {asm.risk_level}
                </span>
            </div>
        </div>
        <div class="summary-metric">
            <div class="summary-label">Findings Requiring Review</div>
            <div class="summary-value">{asm.total_findings}</div>
        </div>
        <div class="summary-metric">
            <div class="summary-label">AI Traffic Confidence</div>
            <div class="summary-value">{avg_conf}%</div>
        </div>
        <div class="summary-metric">
            <div class="summary-label">VPN Mode</div>
            <div class="summary-value" style="font-family: monospace; font-size: 18px;">
                {analysis.ipsec_session.vpn_mode} ({analysis.ipsec_session.ipsec_protocol})
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Findings Table
    st.markdown("### Security Findings")
    if not asm.findings:
        st.info("No security weaknesses or configuration deviations detected for this capture profile.")
    else:
        table_rows = []
        for f in asm.findings:
            table_rows.append({
                "Severity": f.severity,
                "Finding Title": f.title,
                "Category": f.category,
                "Status": f.status,
                "Standard Reference": f.reference
            })
        df_findings = pd.DataFrame(table_rows)
        st.dataframe(
            df_findings,
            column_config={
                "Severity": st.column_config.TextColumn("Severity", width="small"),
                "Finding Title": st.column_config.TextColumn("Finding Title", width="large"),
                "Category": st.column_config.TextColumn("Category", width="medium"),
                "Status": st.column_config.TextColumn("Status", width="medium"),
                "Standard Reference": st.column_config.TextColumn("Standard Reference", width="medium"),
            },
            hide_index=True,
            use_container_width=True
        )

    # Compact Analysis Summary
    st.markdown("### Analysis Summary")
    st.markdown(f"> {asm.summary}")

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Session & Cipher Profile**")
        st.markdown(f"- **Gateway Pair**: `{analysis.ipsec_session.src_endpoint}` ↔ `{analysis.ipsec_session.dst_endpoint}`")
        st.markdown(f"- **IKE Version**: `{analysis.ipsec_session.ike_version}`")
        st.markdown(f"- **Encryption Suite**: `{analysis.ipsec_session.security_association.encryption_algorithm}`")
        st.markdown(f"- **Integrity Suite**: `{analysis.ipsec_session.security_association.integrity_algorithm}`")

    with c2:
        st.markdown("**Traffic & Posture Metrics**")
        st.markdown(f"- **Packets Analyzed**: `{analysis.capture_summary.packet_count:,}`")
        st.markdown(f"- **Volume**: `{analysis.capture_summary.byte_count:,} bytes`")
        st.markdown(f"- **DH Group**: `{analysis.ipsec_session.security_association.dh_group}`")
        st.markdown(f"- **Anti-Replay**: `{'Enabled (Window ' + str(analysis.ipsec_session.security_association.replay_window_size) + ')' if analysis.ipsec_session.security_association.replay_protection_enabled else 'Disabled'}`")
