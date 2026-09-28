"""
IPsecAI Data Models & Normalized Schemas
Defines core data structures for captures, flows, IPsec sessions, findings, assessments, and ML results.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime


class FlowMetadata(BaseModel):
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str = "ESP"
    packet_count: int
    byte_count: int
    duration_seconds: float
    avg_packet_size: float
    packet_size_std: float
    avg_interarrival_ms: float
    interarrival_std_ms: float
    bytes_ratio_in_out: float
    burst_count: int
    first_seen: str
    last_seen: str


class IKEExchange(BaseModel):
    exchange_type: str = "IKE_SA_INIT"  # IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA, INFORMATIONAL
    ike_version: str = "IKEv2"          # IKEv1, IKEv2
    initiator_spi: str
    responder_spi: str
    message_id: int = 0
    proposals_matched: List[str] = Field(default_factory=list)
    dh_group: str = "Group 14"
    encryption_algorithm: str = "AES-256-GCM"
    integrity_algorithm: str = "AEAD (Built-in)"
    prf_algorithm: str = "PRF-HMAC-SHA2-256"


class SecurityAssociation(BaseModel):
    spi_in: str
    spi_out: str
    protocol: str = "ESP"             # ESP, AH
    mode: str = "Tunnel"              # Tunnel, Transport
    encryption_algorithm: str = "AES-256-GCM"
    integrity_algorithm: str = "AEAD (Built-in)"
    dh_group: str = "Group 14"
    pfs_enabled: bool = True
    replay_protection_enabled: bool = True
    replay_window_size: int = 64
    sa_lifetime_seconds: int = 28800
    sa_volume_limit_mb: int = 4096
    metadata_padding_enabled: bool = False
    ip_version: str = "IPv4"


class IPsecSession(BaseModel):
    session_id: str
    src_endpoint: str
    dst_endpoint: str
    vpn_mode: str = "Tunnel"
    ipsec_protocol: str = "ESP"
    ike_version: str = "IKEv2"
    ike_exchange: Optional[IKEExchange] = None
    security_association: SecurityAssociation
    total_packets: int = 0
    total_bytes: int = 0
    duration_seconds: float = 0.0


class FeatureContribution(BaseModel):
    feature_name: str
    feature_value: float
    importance_score: float
    description: str


class ClassificationResult(BaseModel):
    flow_id: str
    predicted_class: str              # Web Browsing, VoIP, Video Streaming, Email, Messaging, ICMP
    confidence_score: float           # 0.0 to 1.0
    probabilities: Dict[str, float]
    top_features: List[FeatureContribution] = Field(default_factory=list)
    inference_method: str = "XGBoost Flow Metadata Inference (Observable statistical features)"
    disclaimer: str = "Inferred from observable flow statistical characteristics; payloads remain encrypted."


class Finding(BaseModel):
    id: str
    rule_id: str
    title: str
    severity: str                     # High, Medium, Low, Informational
    category: str                     # Cryptography, Authentication, Key Exchange, PFS, Replay Protection, SA Lifetime, Configuration, Metadata Exposure
    evidence: str
    impact: str
    recommendation: str
    reference: str
    confidence: float = 1.0           # 1.0 for deterministic rule engine
    status: str = "Action Required"   # Action Required, Under Review, Acceptable Risk
    likelihood: str = "Medium"        # High, Medium, Low
    impact_level: str = "Medium"      # High, Medium, Low


class CategoryAssessment(BaseModel):
    category: str
    result: str                       # Pass, Review, Concern
    score_contribution: int           # E.g. -10, 0
    details: str


class SecurityScoreBreakdown(BaseModel):
    base_score: int = 100
    total_deductions: int = 0
    final_score: int = 100
    risk_level: str = "Low"           # Low, Medium, High, Critical
    deductions: List[Dict[str, Any]] = Field(default_factory=list)
    methodology: str = "Heuristic weighted prototype assessment grounded in NIST SP 800-77 Rev. 1 guidelines."


class SecurityAssessment(BaseModel):
    assessment_id: str
    overall_score: int
    risk_level: str
    summary: str
    categories: List[CategoryAssessment]
    score_breakdown: SecurityScoreBreakdown
    findings: List[Finding]
    total_findings: int
    evaluated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class CaptureSummary(BaseModel):
    capture_id: str
    filename: str
    source_type: str                  # Real PCAP (TShark), Demo Capture, Synthetic Testbed, Demo Stream
    packet_count: int
    byte_count: int
    duration_seconds: float
    protocols_observed: List[str]
    src_endpoints: List[str]
    dst_endpoints: List[str]
    ip_versions: List[str]
    capture_start_time: str
    capture_end_time: str
    parser_status: str                # Parsed via TShark, Simulated Demo Fallback, Zeek Enriched


class ObservedParameter(BaseModel):
    parameter: str
    value: str
    source: str                       # Observed, AI-Inferred, Rule-Based Assessment
    notes: Optional[str] = None


class AnalysisResult(BaseModel):
    analysis_id: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    capture_summary: CaptureSummary
    ipsec_session: IPsecSession
    observed_parameters: List[ObservedParameter]
    flows: List[FlowMetadata]
    traffic_classifications: List[ClassificationResult]
    security_assessment: SecurityAssessment
    is_demo: bool = False
    demo_profile_name: Optional[str] = None
    tshark_available: bool = False
    zeek_available: bool = False


class TestbedRequest(BaseModel):
    vpn_mode: str = "Tunnel"          # Tunnel, Transport
    encryption_algorithm: str = "AES-256-GCM"  # AES-128-GCM, AES-256-GCM, AES-CBC-HMAC, 3DES-CBC
    dh_group: str = "Group 14"        # Group 14, Group 19, Group 20, Group 5
    pfs_enabled: bool = True
    replay_protection: bool = True
    ip_version: str = "IPv4"          # IPv4, IPv6
    traffic_type: str = "Video"       # Web Browsing, VoIP, Email, Messaging, Video, ICMP
    lifetime_hours: int = 8


class TestbedProfile(BaseModel):
    profile_id: str
    generated_at: str
    parameters: TestbedRequest
    expected_security_score: int
    expected_risk_level: str
    expected_findings_count: int
    traffic_characteristics: Dict[str, Any]
    strongswan_conf: str
    swanctl_conf: str
    disclaimer: str = "Prototype configuration template for authorized lab and testing testbeds."
