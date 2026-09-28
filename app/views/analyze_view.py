"""
IPsecAI - Analyze View
Core capture analysis interface showing TShark parser extraction, observed parameters,
and AI-assisted encrypted traffic classification based on observable flow statistics.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from backend.models.schema import AnalysisResult
from backend.streaming.stream_engine import StreamEngine

stream_engine = StreamEngine()


def render_analyze(analysis: AnalysisResult, on_upload_callback, on_load_demo_callback):
    st.markdown("""
    <div class="main-header">
        <h1 class="main-title">Analyze IPsec Traffic</h1>
        <div class="main-subtitle">
            Parse capture files, extract IKE/ESP protocol parameters, and infer traffic flow characteristics from observable metadata.
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Environment Status Banner
    if not analysis.tshark_available:
        st.markdown("""
        <div class="info-banner">
            <strong>Engine Status:</strong> Live packet parsing via TShark is unavailable in this environment (binary not detected).
            Full analysis pipeline is active using standardized demo profiles and synthetic testbed streams.
        </div>
        """, unsafe_allow_html=True)

    # Ingestion Controls
    c_upload, c_demo = st.columns([1.5, 1])
    with c_upload:
        uploaded_file = st.file_uploader(
            "Upload PCAP / PCAPNG capture file",
            type=["pcap", "pcapng", "cap"],
            help="Upload an authorized network packet capture for IPsec/IKE extraction."
        )
        if uploaded_file is not None:
            if st.button("Analyze Uploaded File", type="primary"):
                with st.spinner("Parsing packet capture headers..."):
                    on_upload_callback(uploaded_file)
                st.rerun()

    with c_demo:
        st.markdown("**Load Profile / Simulate Stream**")
        demo_prof = st.selectbox(
            "Select Profile",
            ["Demo A (Healthy Configuration)", "Demo B (Weak Configuration)", "Demo C (Encrypted Multi-Flow)"],
            label_visibility="collapsed"
        )
        col_d1, col_d2 = st.columns(2)
        with col_d1:
            if st.button("Load Profile", use_container_width=True):
                if "Demo A" in demo_prof:
                    on_load_demo_callback("demo_a")
                elif "Demo B" in demo_prof:
                    on_load_demo_callback("demo_b")
                else:
                    on_load_demo_callback("demo_c")
                st.rerun()
        with col_d2:
            show_stream = st.checkbox("Live Demo Stream", value=False)

    # Live Stream Section if toggled
    if show_stream:
        st.markdown("### Live Simulated Stream (In-Process Generator)")
        st.caption("Simulates real-time ESP flow arrivals with instant AI traffic inference.")
        stream_batch = stream_engine.generate_live_stream_batch(count=6)
        df_stream = pd.DataFrame(stream_batch)
        st.dataframe(
            df_stream,
            hide_index=True,
            use_container_width=True,
            column_config={
                "time": st.column_config.TextColumn("Timestamp", width="small"),
                "flow_id": st.column_config.TextColumn("Flow ID", width="small"),
                "endpoints": st.column_config.TextColumn("Endpoints", width="medium"),
                "packet_count": st.column_config.NumberColumn("Packets", width="small"),
                "bytes": st.column_config.TextColumn("Bytes", width="small"),
                "protocol": st.column_config.TextColumn("Protocol", width="small"),
                "inferred_traffic_type": st.column_config.TextColumn("Inferred Type", width="medium"),
                "ai_confidence": st.column_config.TextColumn("AI Confidence", width="small"),
                "source": st.column_config.TextColumn("Source", width="small"),
            }
        )
        st.markdown("---")

    # Capture Summary Section
    st.markdown("### Capture Summary")
    s = analysis.capture_summary
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Packets", f"{s.packet_count:,}")
    c2.metric("Duration", f"{s.duration_seconds}s")
    c3.metric("Volume", f"{s.byte_count:,} B")
    c4.metric("IP Version", ", ".join(s.ip_versions))

    st.markdown(f"- **Source Gateways**: `{', '.join(s.src_endpoints)}` | **Destination Gateways**: `{', '.join(s.dst_endpoints)}`")
    st.markdown(f"- **Protocols Observed**: `{', '.join(s.protocols_observed)}` | **Pipeline Status**: `{s.parser_status}`")

    # Observed vs AI-Inferred Parameters
    st.markdown("### Protocol & Security Parameters")
    st.caption("Clear distinction between directly observed protocol parameters and AI-inferred traffic characteristics.")

    param_rows = []
    for p in analysis.observed_parameters:
        param_rows.append({
            "Observed Parameter": p.parameter,
            "Value": p.value,
            "Source": p.source,
            "Verification Notes": p.notes or ""
        })
    df_params = pd.DataFrame(param_rows)
    st.dataframe(
        df_params,
        hide_index=True,
        use_container_width=True,
        column_config={
            "Observed Parameter": st.column_config.TextColumn("Observed Parameter", width="medium"),
            "Value": st.column_config.TextColumn("Value", width="large"),
            "Source": st.column_config.TextColumn("Source", width="small"),
            "Verification Notes": st.column_config.TextColumn("Verification Notes", width="large")
        }
    )

    # AI-Assisted Traffic Classification
    st.markdown("### AI-Assisted Encrypted Traffic Classification")
    st.markdown("""
    > **Methodology Statement**: Traffic types are inferred exclusively from observable statistical flow metadata
    > (packet length distributions, inter-arrival times, byte ratios, and burst rates).
    > **Payloads remain encrypted; no payload inspection or decryption is performed.**
    """)

    clf_rows = []
    for clf, flow in zip(analysis.traffic_classifications, analysis.flows):
        top_f = ", ".join([f"{tf.feature_name}={tf.feature_value}" for tf in clf.top_features[:2]])
        clf_rows.append({
            "Flow ID": clf.flow_id,
            "Protocol": flow.protocol,
            "Packets": flow.packet_count,
            "Volume (Bytes)": f"{flow.byte_count:,}",
            "Duration (s)": flow.duration_seconds,
            "Mean Pkt Size (B)": flow.avg_packet_size,
            "Mean IAT (ms)": flow.avg_interarrival_ms,
            "Inferred Application": clf.predicted_class,
            "AI Confidence": f"{int(clf.confidence_score * 100)}%",
            "Key Observable Features": top_f
        })
    df_clf = pd.DataFrame(clf_rows)
    st.dataframe(df_clf, hide_index=True, use_container_width=True)

    # Feature Importance Visualization
    st.markdown("#### Observable Feature Importance Ranking")
    if analysis.traffic_classifications and analysis.traffic_classifications[0].top_features:
        sample_top = analysis.traffic_classifications[0].top_features
        feat_df = pd.DataFrame([
            {"Feature": f.description, "Importance Weight": f.importance_score}
            for f in sample_top
        ]).sort_values(by="Importance Weight", ascending=True)

        fig = px.bar(
            feat_df,
            x="Importance Weight",
            y="Feature",
            orientation="h",
            title="Relative Feature Importance for Statistical Flow Classification",
            color_discrete_sequence=["#2563eb"],
            height=260
        )
        fig.update_layout(
            margin=dict(l=20, r=20, t=35, b=20),
            plot_bgcolor="#ffffff",
            paper_bgcolor="#ffffff",
            font=dict(family="Inter", size=12, color="#0f172a"),
            xaxis=dict(showgrid=True, gridcolor="#e2e8f0"),
            yaxis=dict(showgrid=False)
        )
        st.plotly_chart(fig, use_container_width=True)

    with st.expander("Model Details & Explainability"):
        st.markdown("""
        - **Architecture**: XGBoost / Gradient Boosted Decision Trees on statistical flow descriptors.
        - **Training Dataset**: Empirical networking flow distributions (packet lengths, inter-arrival time jitter, directional byte ratios, burst clustering).
        - **Classes Evaluated**: Web Browsing, VoIP (RTP/ESP), Video Streaming, Secure Email, Instant Messaging, ICMP Keepalives.
        - **Honesty Notice**: *Prototype model trained on synthetic/demo flow distributions. Statistical inference indicates behavioral traffic patterns without inspecting encrypted payloads.*
        """)
