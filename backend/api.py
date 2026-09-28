"""
IPsecAI Backend API
FastAPI implementation exposing endpoints for PCAP analysis, demo profiles, security assessments, reports, and testbed generation.
"""

import os
import json
import tempfile
import uuid
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, UploadFile, File, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse

from backend.models.schema import (
    AnalysisResult,
    Finding,
    SecurityAssessment,
    TestbedRequest,
    TestbedProfile,
    CaptureSummary,
    ObservedParameter
)
from backend.parsers.tshark_parser import TSharkParser
from backend.parsers.zeek_parser import ZeekParser
from backend.parsers.synthetic_generator import SyntheticProfileGenerator
from backend.assessment.rule_engine import RuleEngine
from backend.assessment.scoring_engine import ScoringEngine
from backend.ml.traffic_classifier import TrafficClassifier
from backend.ml.dataset_generator import generate_synthetic_flow_dataset
from backend.testbed.testbed_generator import TestbedGenerator
from backend.streaming.stream_engine import StreamEngine
from backend.reporting.report_generator import ReportGenerator
from backend.database.db import DatabaseManager

app = FastAPI(
    title="IPsecAI Security API",
    description="AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework",
    version="1.0.0"
)

# Enable CORS for local dev / dashboard integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize engines
tshark_parser = TSharkParser()
zeek_parser = ZeekParser()
synthetic_gen = SyntheticProfileGenerator()
rule_engine = RuleEngine()
scoring_engine = ScoringEngine()
classifier = TrafficClassifier()
testbed_gen = TestbedGenerator()
stream_engine = StreamEngine()
report_gen = ReportGenerator()
db = DatabaseManager()


@app.get("/health")
def health_check() -> Dict[str, Any]:
    return {
        "status": "healthy",
        "service": "IPsecAI Security Assessment Engine",
        "version": "1.0.0",
        "tshark_installed": tshark_parser.is_available,
        "tshark_version": tshark_parser.version_info,
        "zeek_installed": zeek_parser.is_available,
        "zeek_version": zeek_parser.version_info,
        "active_rules_count": len(rule_engine.rules),
        "ml_engine_ready": True
    }


@app.get("/demo/load")
def load_demo_profile(profile: str = Query(default="demo_a", description="demo_a, demo_b, or demo_c")) -> AnalysisResult:
    """
    Loads one of the pre-configured synthetic demo profiles.
    """
    result = synthetic_gen.generate_profile(profile)
    result.tshark_available = tshark_parser.is_available
    result.zeek_available = zeek_parser.is_available
    db.save_analysis(result)
    return result


@app.post("/analyze/pcap")
async def analyze_pcap(file: UploadFile = File(...)) -> AnalysisResult:
    """
    Uploads and analyzes a PCAP or PCAPNG capture file.
    """
    filename = file.filename or "uploaded_capture.pcap"
    ext = os.path.splitext(filename)[1].lower()
    if ext not in [".pcap", ".pcapng", ".cap"]:
        raise HTTPException(status_code=400, detail="Unsupported file format. Supported extensions: .pcap, .pcapng, .cap")

    # Write upload to temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        success, cap_summary, session, flows, msg = tshark_parser.parse_pcap(tmp_path)
        
        if not success or not session:
            # If tshark is unavailable or file is unparseable, return fallback demo profile with informative banner
            fallback_res = synthetic_gen.generate_profile("demo_a")
            fallback_res.capture_summary.filename = filename
            fallback_res.capture_summary.source_type = "Uploaded Capture (Fallback Mode)"
            fallback_res.capture_summary.parser_status = msg
            fallback_res.tshark_available = tshark_parser.is_available
            fallback_res.zeek_available = zeek_parser.is_available
            db.save_analysis(fallback_res)
            return fallback_res

        # Evaluate rules & score
        findings = rule_engine.evaluate_session(session)
        assessment = scoring_engine.assess(session, findings)
        classifications = classifier.classify_all_flows(flows)

        # Build observed parameters table
        sa = session.security_association
        observed_params = [
            ObservedParameter(parameter="Protocol", value=f"{session.ipsec_protocol} / {session.ike_version}", source="Observed", notes=f"SPI In: {sa.spi_in}, SPI Out: {sa.spi_out}"),
            ObservedParameter(parameter="VPN Mode", value=session.vpn_mode, source="Observed", notes="Validated packet structure"),
            ObservedParameter(parameter="Encryption Algorithm", value=sa.encryption_algorithm, source="Observed", notes="Parsed proposal"),
            ObservedParameter(parameter="Integrity Algorithm", value=sa.integrity_algorithm, source="Observed", notes="Parsed proposal"),
            ObservedParameter(parameter="Key Exchange / DH", value=sa.dh_group, source="Observed", notes="Group identifier"),
            ObservedParameter(parameter="Perfect Forward Secrecy", value="Enabled" if sa.pfs_enabled else "Disabled", source="Observed", notes="Child SA rekey exchange"),
            ObservedParameter(parameter="Anti-Replay Protection", value="Enabled" if sa.replay_protection_enabled else "Disabled", source="Observed", notes=f"Window size: {sa.replay_window_size}"),
            ObservedParameter(parameter="SA Lifetime", value=f"{sa.sa_lifetime_seconds}s", source="Observed", notes="Lifetime policy"),
            ObservedParameter(parameter="Traffic Type", value=f"{classifications[0].predicted_class} ({int(classifications[0].confidence_score*100)}% conf)" if classifications else "Unknown", source="AI-Inferred", notes="Observable flow features"),
            ObservedParameter(parameter="Overall Security Risk", value=f"{assessment.risk_level} ({assessment.overall_score}/100)", source="Rule-Based Assessment", notes="Deterministic heuristic formula")
        ]

        result = AnalysisResult(
            analysis_id=f"RES-{uuid.uuid4().hex[:8].upper()}",
            capture_summary=cap_summary,
            ipsec_session=session,
            observed_parameters=observed_params,
            flows=flows,
            traffic_classifications=classifications,
            security_assessment=assessment,
            is_demo=False,
            tshark_available=tshark_parser.is_available,
            zeek_available=zeek_parser.is_available
        )

        db.save_analysis(result)
        return result

    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


@app.get("/analysis/{analysis_id}")
def get_analysis(analysis_id: str) -> AnalysisResult:
    result = db.get_analysis(analysis_id)
    if not result:
        # Check if it matches a default demo
        if "DEMO-A" in analysis_id.upper() or "HEALTHY" in analysis_id.upper():
            return synthetic_gen.generate_profile("demo_a")
        elif "DEMO-B" in analysis_id.upper() or "WEAK" in analysis_id.upper():
            return synthetic_gen.generate_profile("demo_b")
        elif "DEMO-C" in analysis_id.upper() or "CLASSIFY" in analysis_id.upper():
            return synthetic_gen.generate_profile("demo_c")
        raise HTTPException(status_code=404, detail=f"Analysis ID {analysis_id} not found.")
    return result


@app.get("/analysis/{analysis_id}/findings")
def get_analysis_findings(analysis_id: str) -> List[Finding]:
    res = get_analysis(analysis_id)
    return res.security_assessment.findings


@app.get("/analysis/{analysis_id}/assessment")
def get_analysis_assessment(analysis_id: str) -> SecurityAssessment:
    res = get_analysis(analysis_id)
    return res.security_assessment


@app.get("/analysis/{analysis_id}/report")
def get_analysis_report(analysis_id: str, format: str = Query(default="markdown", description="markdown, html, json, csv")) -> Any:
    res = get_analysis(analysis_id)
    if format.lower() == "html":
        return HTMLResponse(content=report_gen.generate_html_report(res))
    elif format.lower() == "json":
        return JSONResponse(content=json.loads(report_gen.generate_json_export(res)))
    elif format.lower() == "csv":
        return PlainTextResponse(content=report_gen.generate_findings_csv(res), media_type="text/csv")
    else:
        return PlainTextResponse(content=report_gen.generate_technical_report_markdown(res), media_type="text/markdown")


@app.post("/testbed/generate")
def generate_testbed(req: TestbedRequest) -> TestbedProfile:
    return testbed_gen.generate_test_profile(req)


@app.get("/demo/stream")
def get_stream_batch(count: int = Query(default=5, ge=1, le=50)) -> List[Dict[str, Any]]:
    return stream_engine.generate_live_stream_batch(count)


@app.get("/dataset/sample")
def get_dataset_sample(samples_per_class: int = Query(default=10, ge=1, le=100)) -> List[Dict[str, Any]]:
    df = generate_synthetic_flow_dataset(samples_per_class=samples_per_class)
    return df.to_dict(orient="records")
