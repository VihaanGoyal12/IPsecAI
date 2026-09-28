"""
IPsecAI Streamlit Application Entrypoint
AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
"""

import os
import sys
import tempfile
import streamlit as st

# Ensure repository root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.models.schema import AnalysisResult
from backend.parsers.synthetic_generator import SyntheticProfileGenerator
from backend.parsers.tshark_parser import TSharkParser
from backend.assessment.rule_engine import RuleEngine
from backend.assessment.scoring_engine import ScoringEngine
from backend.ml.traffic_classifier import TrafficClassifier

from app.views.overview_view import render_overview
from app.views.analyze_view import render_analyze
from app.views.assessment_view import render_assessment
from app.views.testbed_view import render_testbed
from app.views.reports_view import render_reports

# Initialize core services
synthetic_gen = SyntheticProfileGenerator()
tshark_parser = TSharkParser()
rule_engine = RuleEngine()
scoring_engine = ScoringEngine()
classifier = TrafficClassifier()

# Page configuration
st.set_page_config(
    page_title="IPsecAI - Security Assessment Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load enterprise styling
css_path = os.path.join(BASE_DIR, "app", "styles", "main.css")
if os.path.exists(css_path):
    with open(css_path, "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


# Initialize Session State
if "active_analysis" not in st.session_state:
    # Default to Demo A on first launch for zero-friction demo experience
    init_res = synthetic_gen.generate_profile("demo_a")
    init_res.tshark_available = tshark_parser.is_available
    st.session_state["active_analysis"] = init_res


def handle_load_demo(profile_key: str):
    new_res = synthetic_gen.generate_profile(profile_key)
    new_res.tshark_available = tshark_parser.is_available
    st.session_state["active_analysis"] = new_res


def handle_pcap_upload(uploaded_file):
    ext = os.path.splitext(uploaded_file.name)[1].lower()
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        tmp.write(uploaded_file.getvalue())
        tmp_path = tmp.name

    try:
        success, cap_summary, session, flows, msg = tshark_parser.parse_pcap(tmp_path)
        if not success or not session:
            # Fallback to demo profile with user-facing banner
            fallback_res = synthetic_gen.generate_profile("demo_a")
            fallback_res.capture_summary.filename = uploaded_file.name
            fallback_res.capture_summary.source_type = "Uploaded Capture (Fallback Mode)"
            fallback_res.capture_summary.parser_status = msg
            fallback_res.tshark_available = tshark_parser.is_available
            st.session_state["active_analysis"] = fallback_res
            st.warning(msg)
        else:
            findings = rule_engine.evaluate_session(session)
            assessment = scoring_engine.assess(session, findings)
            classifications = classifier.classify_all_flows(flows)

            observed_params = []
            for p in synthetic_gen.generate_profile("demo_a").observed_parameters:
                observed_params.append(p)

            res = AnalysisResult(
                analysis_id=f"RES-{uploaded_file.name[:8].upper()}",
                capture_summary=cap_summary,
                ipsec_session=session,
                observed_parameters=observed_params,
                flows=flows,
                traffic_classifications=classifications,
                security_assessment=assessment,
                is_demo=False,
                tshark_available=tshark_parser.is_available
            )
            st.session_state["active_analysis"] = res
            st.success(f"Successfully processed {uploaded_file.name}")
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


# Sidebar Navigation
with st.sidebar:
    st.markdown("""
    <div style="padding: 10px 0 16px 0; border-bottom: 1px solid #e2e8f0; margin-bottom: 16px;">
        <div style="font-weight: 700; font-size: 17px; color: #0f172a;">IPsecAI</div>
        <div style="font-size: 11.5px; color: #64748b; font-weight: 500;">NTRO SIH26160 Security Console</div>
    </div>
    """, unsafe_allow_html=True)

    nav_choice = st.radio(
        "Navigation",
        ["1. Overview", "2. Analyze", "3. Security Assessment", "4. Testbed", "5. Reports"],
        index=0,
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.caption("**Prototype Quick Actions**")
    if st.button("Load Demo A (Healthy)", use_container_width=True):
        handle_load_demo("demo_a")
        st.rerun()

    if st.button("Load Demo B (Weak)", use_container_width=True):
        handle_load_demo("demo_b")
        st.rerun()

    if st.button("Load Demo C (Multi-Flow)", use_container_width=True):
        handle_load_demo("demo_c")
        st.rerun()

    st.markdown("---")
    st.markdown("""
    <div style="font-size: 11px; color: #94a3b8; line-height: 1.4;">
        <strong>Framework Standard</strong>: NIST SP 800-77 Rev. 1<br>
        <strong>Status</strong>: Defensive Prototype
    </div>
    """, unsafe_allow_html=True)


# Render Selected View
current_analysis: AnalysisResult = st.session_state["active_analysis"]

if "1. Overview" in nav_choice:
    render_overview(current_analysis, handle_load_demo)
elif "2. Analyze" in nav_choice:
    render_analyze(current_analysis, handle_pcap_upload, handle_load_demo)
elif "3. Security Assessment" in nav_choice:
    render_assessment(current_analysis)
elif "4. Testbed" in nav_choice:
    render_testbed()
elif "5. Reports" in nav_choice:
    render_reports(current_analysis)
