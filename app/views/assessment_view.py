"""
IPsecAI - Security Assessment View
Displays overall heuristic score, category assessment (Pass/Review/Concern),
minimal 2-axis Threat Matrix (Likelihood vs Impact), score deduction breakdown, and findings.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from backend.models.schema import AnalysisResult


def render_assessment(analysis: AnalysisResult):
    st.markdown("""
    <div class="main-header">
        <h1 class="main-title">Security Assessment & Risk Engine</h1>
        <div class="main-subtitle">
            Deterministic security audit grounded in NIST SP 800-77 Rev. 1, RFC 7296 (IKEv2), and RFC 4301.
        </div>
    </div>
    """, unsafe_allow_html=True)

    asm = analysis.security_assessment
    sb = asm.score_breakdown

    # Overall Score & Summary
    col_score, col_summary = st.columns([1, 2.5])
    with col_score:
        score_color = "#15803d" if asm.overall_score >= 85 else ("#b45309" if asm.overall_score >= 70 else "#b91c1c")
        st.markdown(f"""
        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 4px; padding: 20px; text-align: center;">
            <div style="font-size: 12px; font-weight: 600; text-transform: uppercase; color: #64748b; letter-spacing: 0.05em;">
                Prototype Security Score
            </div>
            <div style="font-size: 40px; font-weight: 700; color: {score_color}; margin: 8px 0;">
                {asm.overall_score} <span style="font-size: 20px; color: #94a3b8;">/ 100</span>
            </div>
            <div style="font-size: 14px; font-weight: 600; color: {score_color};">
                Risk Level: {asm.risk_level}
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col_summary:
        st.markdown("### Assessment Summary")
        st.markdown(f"> {asm.summary}")
        st.caption(f"Evaluated session `{analysis.ipsec_session.session_id}` across {len(asm.categories)} technical security categories.")

    st.markdown("---")

    # Category Results Table (Pass / Review / Concern)
    st.markdown("### Category Evaluation Breakdown")
    cat_rows = []
    for cat in asm.categories:
        cat_rows.append({
            "Security Category": cat.category,
            "Evaluation Result": cat.result,
            "Score Impact": f"{cat.score_contribution} pts" if cat.score_contribution < 0 else "0 pts",
            "Observed State & Details": cat.details
        })
    df_cat = pd.DataFrame(cat_rows)
    st.dataframe(
        df_cat,
        hide_index=True,
        use_container_width=True,
        column_config={
            "Security Category": st.column_config.TextColumn("Security Category", width="medium"),
            "Evaluation Result": st.column_config.TextColumn("Evaluation Result", width="small"),
            "Score Impact": st.column_config.TextColumn("Score Impact", width="small"),
            "Observed State & Details": st.column_config.TextColumn("Observed State & Details", width="large")
        }
    )

    # 2-Axis Threat Matrix
    st.markdown("### Threat & Risk Matrix")
    st.caption("Minimal 2-axis risk mapping (Likelihood vs Impact) for identified configuration findings.")

    if asm.findings:
        matrix_data = []
        for f in asm.findings:
            # Map low/med/high to numeric coordinates
            l_map = {"Low": 1, "Medium": 2, "High": 3}
            i_map = {"Low": 1, "Medium": 2, "High": 3}
            matrix_data.append({
                "Finding": f"{f.title} ({f.id})",
                "Likelihood": f.likelihood,
                "Impact": f.impact_level,
                "Likelihood_Score": l_map.get(f.likelihood, 2),
                "Impact_Score": i_map.get(f.impact_level, 2),
                "Severity": f.severity
            })
        
        df_matrix = pd.DataFrame(matrix_data)
        fig = px.scatter(
            df_matrix,
            x="Likelihood_Score",
            y="Impact_Score",
            text="Finding",
            color="Severity",
            color_discrete_map={"High": "#b91c1c", "Medium": "#b45309", "Low": "#15803d"},
            range_x=[0.5, 3.5],
            range_y=[0.5, 3.5],
            height=320
        )
        fig.update_traces(textposition="top center", marker=dict(size=12, line=dict(width=1, color="#0f172a")))
        fig.update_layout(
            margin=dict(l=40, r=40, t=30, b=30),
            plot_bgcolor="#f8fafc",
            paper_bgcolor="#ffffff",
            font=dict(family="Inter", size=11, color="#0f172a"),
            xaxis=dict(
                title="Likelihood of Exposure",
                tickvals=[1, 2, 3],
                ticktext=["Low", "Medium", "High"],
                showgrid=True,
                gridcolor="#e2e8f0"
            ),
            yaxis=dict(
                title="Potential Security Impact",
                tickvals=[1, 2, 3],
                ticktext=["Low", "Medium", "High"],
                showgrid=True,
                gridcolor="#e2e8f0"
            )
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No findings present to plot on the threat matrix.")

    # Detailed Findings Section
    st.markdown("### Detailed Identified Findings")
    if not asm.findings:
        st.success("All cryptographic and configuration parameters satisfy standard security guidelines.")
    else:
        for f in asm.findings:
            sev_badge = f.severity.upper()
            st.markdown(f"""
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-left: 4px solid {'#b91c1c' if f.severity == 'High' else ('#b45309' if f.severity == 'Medium' else '#15803d')}; padding: 16px; border-radius: 4px; margin-bottom: 14px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="font-weight: 700; font-size: 15px; color: #0f172a;">
                        [{f.severity}] {f.title} <span style="font-family: monospace; font-size: 13px; color: #64748b;">({f.rule_id})</span>
                    </div>
                    <div style="font-size: 12px; font-weight: 600; color: #475569;">
                        Category: {f.category}
                    </div>
                </div>
                <div style="margin-top: 8px; font-size: 13.5px; color: #334155;">
                    <p style="margin: 4px 0;"><strong>Observed Evidence:</strong> <code>{f.evidence}</code></p>
                    <p style="margin: 4px 0;"><strong>Security Impact:</strong> {f.impact}</p>
                    <p style="margin: 4px 0; color: #1d4ed8;"><strong>Remediation Recommendation:</strong> {f.recommendation}</p>
                    <p style="margin: 4px 0; font-size: 12px; color: #64748b;"><strong>Authoritative Reference:</strong> {f.reference}</p>
                </div>
            </div>
            """, unsafe_allow_html=True)

    # Transparent Scoring Calculation Breakdown
    with st.expander("How this score is calculated (Transparent Deduction Breakdown)"):
        st.markdown(f"""
        - **Base Score**: `100 points`
        - **Methodology**: {sb.methodology}
        - **Total Deductions**: `-{sb.total_deductions} points`
        - **Calculated Final Score**: `max(0, 100 - {sb.total_deductions}) = {sb.final_score} / 100`
        """)

        if sb.deductions:
            df_ded = pd.DataFrame(sb.deductions)
            st.dataframe(
                df_ded,
                hide_index=True,
                use_container_width=True,
                column_config={
                    "rule_id": st.column_config.TextColumn("Rule ID", width="small"),
                    "title": st.column_config.TextColumn("Finding Title", width="large"),
                    "category": st.column_config.TextColumn("Category", width="medium"),
                    "severity": st.column_config.TextColumn("Severity", width="small"),
                    "penalty": st.column_config.NumberColumn("Penalty (pts)", width="small"),
                    "reason": st.column_config.TextColumn("Evidence", width="large")
                }
            )
        else:
            st.info("Zero penalty deductions applied.")
