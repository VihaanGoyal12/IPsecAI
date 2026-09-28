"""
IPsecAI - Testbed Configurator View
Allows users to configure synthetic IPsec VPN parameters, generate test profiles,
predict expected security assessments, and export strongSwan / swanctl configuration templates.
"""

import streamlit as st
import pandas as pd
from backend.models.schema import TestbedRequest, TestbedProfile
from backend.testbed.testbed_generator import TestbedGenerator

testbed_gen = TestbedGenerator()


def render_testbed():
    st.markdown("""
    <div class="main-header">
        <h1 class="main-title">IPsec VPN Testbed Configurator</h1>
        <div class="main-subtitle">
            Configure VPN testbed scenarios, preview expected security outcomes, and generate strongSwan / swanctl deployment templates.
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="info-banner">
        <strong>Lab Notice:</strong> Generates prototype configuration templates and deterministic testbed profiles for authorized research environments.
    </div>
    """, unsafe_allow_html=True)

    # Form Controls
    with st.form("testbed_form"):
        st.markdown("### 1. VPN Tunnel & Cryptographic Parameters")
        c1, c2, c3 = st.columns(3)
        with c1:
            vpn_mode = st.selectbox("VPN Mode", ["Tunnel", "Transport"], index=0, help="Tunnel encapsulates full packet; Transport preserves original IP header.")
            ip_version = st.selectbox("IP Version", ["IPv4", "IPv6"], index=0)
        with c2:
            encryption = st.selectbox("Encryption Algorithm", ["AES-256-GCM", "AES-128-GCM", "AES-128-CBC", "3DES-CBC"], index=0)
            dh_group = st.selectbox("Diffie-Hellman Group", ["Group 14 (MODP-2048)", "Group 19 (ECP-256)", "Group 20 (ECP-384)", "Group 2 (MODP-1024)"], index=0)
        with c3:
            pfs = st.selectbox("Perfect Forward Secrecy (PFS)", ["Enabled", "Disabled"], index=0)
            replay_prot = st.selectbox("Anti-Replay Protection", ["Enabled", "Disabled"], index=0)

        st.markdown("### 2. Traffic Flow & Lifetime Policy")
        c4, c5 = st.columns(2)
        with c4:
            traffic_type = st.selectbox("Target Simulated Traffic Type", ["Video", "VoIP", "Web Browsing", "Email", "Messaging", "ICMP"], index=0)
        with c5:
            lifetime_hours = st.slider("Child SA Lifetime (Hours)", min_value=1, max_value=72, value=8)

        submitted = st.form_submit_button("Generate Test Profile & Config Templates", type="primary")

    if submitted:
        # Map values to model
        clean_dh = dh_group.split(" ")[0] + " " + dh_group.split(" ")[1] if "(" in dh_group else dh_group
        req = TestbedRequest(
            vpn_mode=vpn_mode,
            encryption_algorithm=encryption,
            dh_group=clean_dh,
            pfs_enabled=(pfs == "Enabled"),
            replay_protection=(replay_prot == "Enabled"),
            ip_version=ip_version,
            traffic_type=traffic_type,
            lifetime_hours=lifetime_hours
        )

        profile: TestbedProfile = testbed_gen.generate_test_profile(req)
        st.session_state["active_testbed_profile"] = profile

    if "active_testbed_profile" in st.session_state:
        prof: TestbedProfile = st.session_state["active_testbed_profile"]

        st.markdown("---")
        st.markdown(f"### Generated Testbed Profile: `{prof.profile_id}`")
        
        # Summary row
        c_score, c_risk, c_findings = st.columns(3)
        c_score.metric("Expected Security Score", f"{prof.expected_security_score} / 100")
        c_risk.metric("Expected Risk Level", prof.expected_risk_level)
        c_findings.metric("Expected Findings", f"{prof.expected_findings_count} concerns")

        # Traffic flow profile
        st.markdown("#### Expected Traffic Characteristics")
        if prof.traffic_characteristics:
            t_df = pd.DataFrame([prof.traffic_characteristics])
            st.dataframe(t_df, hide_index=True, use_container_width=True)

        # Configuration Snippets
        st.markdown("#### Generated strongSwan Template (`ipsec.conf`)")
        st.code(prof.strongswan_conf, language="ini")

        st.markdown("#### Generated Modern swanctl Template (`swanctl.conf`)")
        st.code(prof.swanctl_conf, language="conf")

        st.caption(f"Disclaimer: {prof.disclaimer}")
