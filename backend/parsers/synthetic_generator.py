"""
IPsecAI Synthetic Demo Profile Generator
Produces realistic, fully populated IPsec capture profiles for demonstration without requiring physical VPN gateways.
Profiles:
- DEMO A: Healthy Enterprise Tunnel (AES-256-GCM, DH Group 14/19, PFS Enabled, Replay Protection Enabled)
- DEMO B: Weak / Vulnerable Configuration (Transport Mode, AES-CBC+HMAC-SHA1, PFS Disabled, Long SA Lifetime)
- DEMO C: Multi-Flow Encrypted Traffic Classification (6 Application Types: Web, VoIP, Video, Email, Messaging, ICMP)
"""

from typing import List, Dict, Any, Tuple
from datetime import datetime
import numpy as np

from backend.models.schema import (
    CaptureSummary,
    IPsecSession,
    IKEExchange,
    SecurityAssociation,
    FlowMetadata,
    ObservedParameter,
    AnalysisResult,
    Finding
)
from backend.assessment.rule_engine import RuleEngine
from backend.assessment.scoring_engine import ScoringEngine
from backend.ml.traffic_classifier import TrafficClassifier


class SyntheticProfileGenerator:
    def __init__(self):
        self.rule_engine = RuleEngine()
        self.scoring_engine = ScoringEngine()
        self.traffic_classifier = TrafficClassifier()

    def generate_profile(self, profile_key: str = "demo_a") -> AnalysisResult:
        if profile_key.lower() == "demo_b":
            return self._build_demo_b_weak()
        elif profile_key.lower() == "demo_c":
            return self._build_demo_c_multi_flow()
        else:
            return self._build_demo_a_healthy()

    def _build_demo_a_healthy(self) -> AnalysisResult:
        """
        DEMO A: Enterprise-grade compliant IPsec tunnel
        """
        sa = SecurityAssociation(
            spi_in="0x4B219E80",
            spi_out="0x99D310FA",
            protocol="ESP",
            mode="Tunnel",
            encryption_algorithm="AES-256-GCM",
            integrity_algorithm="AEAD (Built-in ICV-128)",
            dh_group="Group 14",
            pfs_enabled=True,
            replay_protection_enabled=True,
            replay_window_size=128,
            sa_lifetime_seconds=28800,  # 8 hours
            sa_volume_limit_mb=4096,
            metadata_padding_enabled=True,
            ip_version="IPv4"
        )

        ike_ex = IKEExchange(
            exchange_type="IKE_SA_INIT",
            ike_version="IKEv2",
            initiator_spi="0x91F032B7A14C8092",
            responder_spi="0x52E809CD112A3467",
            message_id=0,
            proposals_matched=["ENCR_AES_GCM_16_256", "PRF_HMAC_SHA2_256", "DH_MODP_2048"],
            dh_group="Group 14",
            encryption_algorithm="AES-256-GCM",
            integrity_algorithm="AEAD (Built-in)"
        )

        session = IPsecSession(
            session_id="SES-PROD-HQ-DC01",
            src_endpoint="198.51.100.14",
            dst_endpoint="203.0.113.88",
            vpn_mode="Tunnel",
            ipsec_protocol="ESP",
            ike_version="IKEv2",
            ike_exchange=ike_ex,
            security_association=sa,
            total_packets=3480,
            total_bytes=4289120,
            duration_seconds=120.0
        )

        summary = CaptureSummary(
            capture_id="CAP-SYNTH-DEMO-A",
            filename="ipsec_enterprise_tunnel_healthy.pcap",
            source_type="Demo Capture (Healthy Profile)",
            packet_count=3480,
            byte_count=4289120,
            duration_seconds=120.0,
            protocols_observed=["ESP (Protocol 50)", "IKEv2 (UDP 500/4500)", "IPv4"],
            src_endpoints=["198.51.100.14"],
            dst_endpoints=["203.0.113.88"],
            ip_versions=["IPv4"],
            capture_start_time="2026-09-28T10:00:00Z",
            capture_end_time="2026-09-28T10:02:00Z",
            parser_status="Simulated Demo Profile (Healthy Configuration)"
        )

        flows = [
            FlowMetadata(
                flow_id="FLOW-A101",
                src_ip="198.51.100.14",
                dst_ip="203.0.113.88",
                src_port=4500,
                dst_port=4500,
                protocol="ESP",
                packet_count=2100,
                byte_count=2780000,
                duration_seconds=118.5,
                avg_packet_size=1323.8,
                packet_size_std=184.2,
                avg_interarrival_ms=14.8,
                interarrival_std_ms=21.4,
                bytes_ratio_in_out=0.07,
                burst_count=16,
                first_seen="2026-09-28T10:00:01Z",
                last_seen="2026-09-28T10:01:59Z"
            ),
            FlowMetadata(
                flow_id="FLOW-A102",
                src_ip="198.51.100.14",
                dst_ip="203.0.113.88",
                src_port=4500,
                dst_port=4500,
                protocol="ESP",
                packet_count=1380,
                byte_count=1509120,
                duration_seconds=115.0,
                avg_packet_size=1093.5,
                packet_size_std=390.1,
                avg_interarrival_ms=83.3,
                interarrival_std_ms=120.5,
                bytes_ratio_in_out=0.32,
                burst_count=9,
                first_seen="2026-09-28T10:00:05Z",
                last_seen="2026-09-28T10:02:00Z"
            )
        ]

        # Security evaluation
        findings = self.rule_engine.evaluate_session(session)
        assessment = self.scoring_engine.assess(session, findings)
        classifications = self.traffic_classifier.classify_all_flows(flows)

        # Build Observed vs AI parameters
        observed_params = [
            ObservedParameter(parameter="Protocol", value="IPsec / IKEv2 (ESP)", source="Observed", notes="IKEv2 handshake & ESP SPI 0x4B219E80"),
            ObservedParameter(parameter="VPN Mode", value="Tunnel", source="Observed", notes="Encapsulating original IP datagram"),
            ObservedParameter(parameter="Encryption Algorithm", value="AES-256-GCM", source="Observed", notes="AEAD authenticated encryption"),
            ObservedParameter(parameter="Integrity / ICV", value="AEAD (Built-in 128-bit)", source="Observed", notes="Native authentication tag"),
            ObservedParameter(parameter="Key Exchange / DH", value="Group 14 (MODP-2048)", source="Observed", notes="NIST SP 800-77 compliant"),
            ObservedParameter(parameter="Perfect Forward Secrecy", value="Enabled", source="Observed", notes="Child SA DH re-exchange active"),
            ObservedParameter(parameter="Anti-Replay Protection", value="Enabled (Window 128)", source="Observed", notes="Sliding window verified"),
            ObservedParameter(parameter="SA Lifetime", value="28,800 sec (8 hours)", source="Observed", notes="Standard operational limit"),
            ObservedParameter(parameter="Traffic Flow A101 Type", value=f"{classifications[0].predicted_class} ({int(classifications[0].confidence_score*100)}% conf)", source="AI-Inferred", notes="Observable flow length & IAT statistics"),
            ObservedParameter(parameter="Traffic Flow A102 Type", value=f"{classifications[1].predicted_class} ({int(classifications[1].confidence_score*100)}% conf)", source="AI-Inferred", notes="Observable burst & duration statistics"),
            ObservedParameter(parameter="Overall Security Risk", value=f"{assessment.risk_level} ({assessment.overall_score}/100)", source="Rule-Based Assessment", notes="Deterministic heuristic formula")
        ]

        return AnalysisResult(
            analysis_id="RES-DEMO-A-HEALTHY",
            capture_summary=summary,
            ipsec_session=session,
            observed_parameters=observed_params,
            flows=flows,
            traffic_classifications=classifications,
            security_assessment=assessment,
            is_demo=True,
            demo_profile_name="Demo A (Healthy Configuration)",
            tshark_available=False,
            zeek_available=False
        )

    def _build_demo_b_weak(self) -> AnalysisResult:
        """
        DEMO B: Weak / Vulnerable Configuration
        """
        sa = SecurityAssociation(
            spi_in="0x11223344",
            spi_out="0x55667788",
            protocol="ESP",
            mode="Transport",             # Weak: Exposes inner headers over transit
            encryption_algorithm="AES-128-CBC",  # Non-AEAD CBC mode
            integrity_algorithm="HMAC-SHA1",    # Deprecated SHA1
            dh_group="Group 2",           # Deprecated MODP-1024
            pfs_enabled=False,            # Weak: No PFS
            replay_protection_enabled=False,  # Weak: Disabled replay window
            replay_window_size=0,
            sa_lifetime_seconds=172800,   # 48 hours (Excessive)
            sa_volume_limit_mb=50000,     # Excessive volume limit
            metadata_padding_enabled=False,
            ip_version="IPv4"
        )

        ike_ex = IKEExchange(
            exchange_type="ISAKMP_MAIN_MODE",
            ike_version="IKEv1",          # Legacy IKEv1
            initiator_spi="0xA0B1C2D3E4F50001",
            responder_spi="0xF0E1D2C3B4A50002",
            message_id=0,
            proposals_matched=["OAKLEY_DES_CBC", "HMAC_SHA1", "MODP_1024"],
            dh_group="Group 2",
            encryption_algorithm="AES-128-CBC",
            integrity_algorithm="HMAC-SHA1"
        )

        session = IPsecSession(
            session_id="SES-LEGACY-SITE02",
            src_endpoint="192.0.2.45",
            dst_endpoint="198.51.100.99",
            vpn_mode="Transport",
            ipsec_protocol="ESP",
            ike_version="IKEv1",
            ike_exchange=ike_ex,
            security_association=sa,
            total_packets=1250,
            total_bytes=980500,
            duration_seconds=300.0
        )

        summary = CaptureSummary(
            capture_id="CAP-SYNTH-DEMO-B",
            filename="ipsec_legacy_vulnerable.pcap",
            source_type="Demo Capture (Weak Configuration)",
            packet_count=1250,
            byte_count=980500,
            duration_seconds=300.0,
            protocols_observed=["ESP (Protocol 50)", "ISAKMP (UDP 500)", "IPv4"],
            src_endpoints=["192.0.2.45"],
            dst_endpoints=["198.51.100.99"],
            ip_versions=["IPv4"],
            capture_start_time="2026-09-28T11:00:00Z",
            capture_end_time="2026-09-28T11:05:00Z",
            parser_status="Simulated Demo Profile (Weak Configuration)"
        )

        flows = [
            FlowMetadata(
                flow_id="FLOW-B201",
                src_ip="192.0.2.45",
                dst_ip="198.51.100.99",
                src_port=500,
                dst_port=500,
                protocol="ESP",
                packet_count=1250,
                byte_count=980500,
                duration_seconds=300.0,
                avg_packet_size=784.4,
                packet_size_std=410.2,
                avg_interarrival_ms=240.0,
                interarrival_std_ms=195.0,
                bytes_ratio_in_out=0.68,
                burst_count=6,
                first_seen="2026-09-28T11:00:00Z",
                last_seen="2026-09-28T11:05:00Z"
            )
        ]

        findings = self.rule_engine.evaluate_session(session)
        assessment = self.scoring_engine.assess(session, findings)
        classifications = self.traffic_classifier.classify_all_flows(flows)

        observed_params = [
            ObservedParameter(parameter="Protocol", value="IPsec / IKEv1 (ISAKMP)", source="Observed", notes="Legacy IKEv1 Main Mode exchange"),
            ObservedParameter(parameter="VPN Mode", value="Transport", source="Observed", notes="Exposes internal IP headers"),
            ObservedParameter(parameter="Encryption Algorithm", value="AES-128-CBC", source="Observed", notes="Non-AEAD cipher mode"),
            ObservedParameter(parameter="Integrity Algorithm", value="HMAC-SHA1", source="Observed", notes="Deprecated SHA-1 hash"),
            ObservedParameter(parameter="Key Exchange / DH", value="Group 2 (MODP-1024)", source="Observed", notes="Insufficient DH bit length"),
            ObservedParameter(parameter="Perfect Forward Secrecy", value="Disabled", source="Observed", notes="No child SA fresh DH exchange"),
            ObservedParameter(parameter="Anti-Replay Protection", value="Disabled", source="Observed", notes="Replay window disabled"),
            ObservedParameter(parameter="SA Lifetime", value="172,800 sec (48 hours)", source="Observed", notes="Exceeds safe limits"),
            ObservedParameter(parameter="Traffic Flow B201 Type", value=f"{classifications[0].predicted_class} ({int(classifications[0].confidence_score*100)}% conf)", source="AI-Inferred", notes="Observable flow length & IAT statistics"),
            ObservedParameter(parameter="Overall Security Risk", value=f"{assessment.risk_level} ({assessment.overall_score}/100)", source="Rule-Based Assessment", notes="Deterministic heuristic formula")
        ]

        return AnalysisResult(
            analysis_id="RES-DEMO-B-WEAK",
            capture_summary=summary,
            ipsec_session=session,
            observed_parameters=observed_params,
            flows=flows,
            traffic_classifications=classifications,
            security_assessment=assessment,
            is_demo=True,
            demo_profile_name="Demo B (Weak Configuration)",
            tshark_available=False,
            zeek_available=False
        )

    def _build_demo_c_multi_flow(self) -> AnalysisResult:
        """
        DEMO C: Multi-Flow Encrypted Traffic Classification Profile
        """
        sa = SecurityAssociation(
            spi_in="0xCAFE0123",
            spi_out="0xBABE9876",
            protocol="ESP",
            mode="Tunnel",
            encryption_algorithm="AES-256-GCM",
            integrity_algorithm="AEAD (Built-in)",
            dh_group="Group 19",          # Modern ECP-256
            pfs_enabled=True,
            replay_protection_enabled=True,
            replay_window_size=64,
            sa_lifetime_seconds=28800,
            sa_volume_limit_mb=4096,
            metadata_padding_enabled=False,
            ip_version="IPv4"
        )

        ike_ex = IKEExchange(
            exchange_type="IKE_SA_INIT",
            ike_version="IKEv2",
            initiator_spi="0x1020304050607080",
            responder_spi="0x8070605040302010",
            message_id=0,
            proposals_matched=["ENCR_AES_GCM_16_256", "PRF_HMAC_SHA2_256", "ECP_256"],
            dh_group="Group 19",
            encryption_algorithm="AES-256-GCM",
            integrity_algorithm="AEAD (Built-in)"
        )

        session = IPsecSession(
            session_id="SES-MULTI-TRAFFIC-LAB",
            src_endpoint="198.51.100.22",
            dst_endpoint="203.0.113.10",
            vpn_mode="Tunnel",
            ipsec_protocol="ESP",
            ike_version="IKEv2",
            ike_exchange=ike_ex,
            security_association=sa,
            total_packets=5210,
            total_bytes=4892000,
            duration_seconds=180.0
        )

        summary = CaptureSummary(
            capture_id="CAP-SYNTH-DEMO-C",
            filename="ipsec_multiflow_classification.pcap",
            source_type="Demo Capture (Encrypted Traffic Classification)",
            packet_count=5210,
            byte_count=4892000,
            duration_seconds=180.0,
            protocols_observed=["ESP (Protocol 50)", "IKEv2 (UDP 500/4500)", "IPv4"],
            src_endpoints=["198.51.100.22"],
            dst_endpoints=["203.0.113.10"],
            ip_versions=["IPv4"],
            capture_start_time="2026-09-28T12:00:00Z",
            capture_end_time="2026-09-28T12:03:00Z",
            parser_status="Simulated Demo Profile (Multi-Flow Encrypted Classification)"
        )

        # 6 flows matching distinct applications
        flows = [
            FlowMetadata(
                flow_id="FLOW-C301 (VoIP)",
                src_ip="198.51.100.22",
                dst_ip="203.0.113.10",
                src_port=4500,
                dst_port=4500,
                protocol="ESP",
                packet_count=550,
                byte_count=99000,
                duration_seconds=11.0,
                avg_packet_size=180.0,
                packet_size_std=14.5,
                avg_interarrival_ms=20.0,
                interarrival_std_ms=3.8,
                bytes_ratio_in_out=1.01,
                burst_count=2,
                first_seen="2026-09-28T12:00:05Z",
                last_seen="2026-09-28T12:00:16Z"
            ),
            FlowMetadata(
                flow_id="FLOW-C302 (Video)",
                src_ip="198.51.100.22",
                dst_ip="203.0.113.10",
                src_port=4500,
                dst_port=4500,
                protocol="ESP",
                packet_count=2200,
                byte_count=2926000,
                duration_seconds=48.0,
                avg_packet_size=1330.0,
                packet_size_std=185.0,
                avg_interarrival_ms=14.5,
                interarrival_std_ms=21.0,
                bytes_ratio_in_out=0.06,
                burst_count=20,
                first_seen="2026-09-28T12:00:10Z",
                last_seen="2026-09-28T12:00:58Z"
            ),
            FlowMetadata(
                flow_id="FLOW-C303 (Web)",
                src_ip="198.51.100.22",
                dst_ip="203.0.113.10",
                src_port=4500,
                dst_port=4500,
                protocol="ESP",
                packet_count=180,
                byte_count=135000,
                duration_seconds=22.0,
                avg_packet_size=750.0,
                packet_size_std=440.0,
                avg_interarrival_ms=122.0,
                interarrival_std_ms=175.0,
                bytes_ratio_in_out=0.34,
                burst_count=8,
                first_seen="2026-09-28T12:00:30Z",
                last_seen="2026-09-28T12:00:52Z"
            ),
            FlowMetadata(
                flow_id="FLOW-C304 (Email)",
                src_ip="198.51.100.22",
                dst_ip="203.0.113.10",
                src_port=4500,
                dst_port=4500,
                protocol="ESP",
                packet_count=65,
                byte_count=36400,
                duration_seconds=15.0,
                avg_packet_size=560.0,
                packet_size_std=310.0,
                avg_interarrival_ms=230.0,
                interarrival_std_ms=155.0,
                bytes_ratio_in_out=0.62,
                burst_count=4,
                first_seen="2026-09-28T12:01:00Z",
                last_seen="2026-09-28T12:01:15Z"
            ),
            FlowMetadata(
                flow_id="FLOW-C305 (Messaging)",
                src_ip="198.51.100.22",
                dst_ip="203.0.113.10",
                src_port=4500,
                dst_port=4500,
                protocol="ESP",
                packet_count=28,
                byte_count=7840,
                duration_seconds=24.0,
                avg_packet_size=280.0,
                packet_size_std=88.0,
                avg_interarrival_ms=850.0,
                interarrival_std_ms=390.0,
                bytes_ratio_in_out=0.88,
                burst_count=3,
                first_seen="2026-09-28T12:01:20Z",
                last_seen="2026-09-28T12:01:44Z"
            ),
            FlowMetadata(
                flow_id="FLOW-C306 (ICMP)",
                src_ip="198.51.100.22",
                dst_ip="203.0.113.10",
                src_port=4500,
                dst_port=4500,
                protocol="ESP",
                packet_count=30,
                byte_count=2520,
                duration_seconds=30.0,
                avg_packet_size=84.0,
                packet_size_std=1.5,
                avg_interarrival_ms=1000.0,
                interarrival_std_ms=10.0,
                bytes_ratio_in_out=1.0,
                burst_count=1,
                first_seen="2026-09-28T12:02:00Z",
                last_seen="2026-09-28T12:02:30Z"
            )
        ]

        findings = self.rule_engine.evaluate_session(session)
        assessment = self.scoring_engine.assess(session, findings)
        classifications = self.traffic_classifier.classify_all_flows(flows)

        observed_params = [
            ObservedParameter(parameter="Protocol", value="IPsec / IKEv2 (ESP)", source="Observed", notes="IKEv2 session active"),
            ObservedParameter(parameter="VPN Mode", value="Tunnel", source="Observed", notes="Encapsulation of inner payloads"),
            ObservedParameter(parameter="Encryption Algorithm", value="AES-256-GCM", source="Observed", notes="AEAD authenticated encryption"),
            ObservedParameter(parameter="Integrity / ICV", value="AEAD (Built-in)", source="Observed", notes="Built-in Galois authentication"),
            ObservedParameter(parameter="Key Exchange / DH", value="Group 19 (ECP-256)", source="Observed", notes="NIST P-256 Elliptic Curve"),
            ObservedParameter(parameter="Perfect Forward Secrecy", value="Enabled", source="Observed", notes="PFS active on child SAs"),
            ObservedParameter(parameter="Anti-Replay Protection", value="Enabled (Window 64)", source="Observed", notes="Anti-replay sliding window"),
            ObservedParameter(parameter="SA Lifetime", value="28,800 sec (8 hours)", source="Observed", notes="Standard lifetime"),
            ObservedParameter(parameter="Encrypted Flows Count", value="6 Active Flows", source="Observed", notes="Statistical metadata monitored"),
            ObservedParameter(parameter="Overall Security Score", value=f"{assessment.overall_score}/100 ({assessment.risk_level} Risk)", source="Rule-Based Assessment", notes="Deterministic heuristic formula")
        ]

        return AnalysisResult(
            analysis_id="RES-DEMO-C-CLASSIFY",
            capture_summary=summary,
            ipsec_session=session,
            observed_parameters=observed_params,
            flows=flows,
            traffic_classifications=classifications,
            security_assessment=assessment,
            is_demo=True,
            demo_profile_name="Demo C (Encrypted Traffic Classification)",
            tshark_available=False,
            zeek_available=False
        )
