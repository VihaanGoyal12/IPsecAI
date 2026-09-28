"""
IPsecAI Report Generation Module
Generates comprehensive Technical Reports and Executive Summaries.
Supports export to HTML, JSON, CSV, and Markdown formats.
"""

import json
import csv
import io
from typing import Dict, Any, List
from datetime import datetime

from backend.models.schema import AnalysisResult


class ReportGenerator:
    def generate_technical_report_markdown(self, analysis: AnalysisResult) -> str:
        s = analysis.capture_summary
        sess = analysis.ipsec_session
        sa = sess.security_association
        asm = analysis.security_assessment
        sb = asm.score_breakdown

        lines = [
            f"# IPsecAI Technical Security Assessment Report",
            f"**Analysis ID**: `{analysis.analysis_id}`  ",
            f"**Generated**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Status**: {'DEMO DATA (Simulated capture)' if analysis.is_demo else 'Real Capture Analysis'}  ",
            "",
            "---",
            "",
            "## 1. Executive Summary & Security Posture",
            "",
            f"- **Prototype Security Score**: **{asm.overall_score} / 100**",
            f"- **Overall Risk Level**: **{asm.risk_level}**",
            f"- **Total Findings**: {asm.total_findings}",
            f"- **Methodology**: {sb.methodology}",
            "",
            f"> {asm.summary}",
            "",
            "---",
            "",
            "## 2. Capture & Endpoint Metadata",
            "",
            f"- **Capture File**: `{s.filename}`",
            f"- **Capture Duration**: {s.duration_seconds} seconds",
            f"- **Total Packets**: {s.packet_count:,}",
            f"- **Total Bytes**: {s.byte_count:,} bytes",
            f"- **Observed Protocols**: {', '.join(s.protocols_observed)}",
            f"- **Source Gateway**: `{sess.src_endpoint}`",
            f"- **Destination Gateway**: `{sess.dst_endpoint}`",
            f"- **IP Versions**: {', '.join(s.ip_versions)}",
            f"- **Parser Pipeline**: {s.parser_status}",
            "",
            "---",
            "",
            "## 3. IPsec & IKE Configuration Identification",
            "",
            "| Parameter | Observed Value | Extraction Source | Verification Notes |",
            "| :--- | :--- | :--- | :--- |",
        ]

        for p in analysis.observed_parameters:
            lines.append(f"| **{p.parameter}** | `{p.value}` | {p.source} | {p.notes or ''} |")

        lines.extend([
            "",
            "---",
            "",
            "## 4. Category Security Assessment",
            "",
            "| Category | Assessment Result | Deduction | Evaluation Details |",
            "| :--- | :--- | :--- | :--- |",
        ])

        for c in asm.categories:
            lines.append(f"| **{c.category}** | {c.result} | {c.score_contribution} pts | {c.details} |")

        lines.extend([
            "",
            "---",
            "",
            "## 5. Security Findings & Identified Weaknesses",
            "",
        ])

        if not asm.findings:
            lines.append("*No security concerns or configuration weaknesses identified for this profile.*")
        else:
            for f in asm.findings:
                lines.extend([
                    f"### [{f.severity}] {f.title} (`{f.rule_id}`)",
                    f"- **Category**: {f.category}",
                    f"- **Status**: `{f.status}` | **Likelihood**: {f.likelihood} | **Impact**: {f.impact_level}",
                    f"- **Evidence**: {f.evidence}",
                    f"- **Security Impact**: {f.impact}",
                    f"- **Recommendation**: {f.recommendation}",
                    f"- **Authoritative Reference**: {f.reference}",
                    ""
                ])

        lines.extend([
            "---",
            "",
            "## 6. AI-Assisted Encrypted Traffic Classification",
            "",
            "> **Methodology Notice**: Inferred strictly from observable flow statistical features (packet lengths, inter-arrival times, burst ratios). Payloads remain encrypted; no decryption or payload inspection was performed.",
            "",
            "| Flow ID | Protocol | Volume | Duration | Inferred Traffic Type | Model Confidence | Top Contributing Features |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ])

        for clf, flow in zip(analysis.traffic_classifications, analysis.flows):
            top_f_str = ", ".join([f"{tf.feature_name} ({tf.feature_value})" for tf in clf.top_features[:2]])
            lines.append(f"| `{clf.flow_id}` | `{flow.protocol}` | {flow.packet_count} pkts ({flow.byte_count:,} B) | {flow.duration_seconds}s | **{clf.predicted_class}** | {int(clf.confidence_score*100)}% | {top_f_str} |")

        lines.extend([
            "",
            "---",
            "",
            "## 7. Prototype Limitations & Research Context",
            "",
            "- **Observable Metadata Only**: Traffic classification is based on statistical features; encrypted payloads are not inspected.",
            "- **Prototype Heuristic**: The security score is a weighted prototype heuristic grounded in NIST SP 800-77 Rev. 1, not an official NTRO certification.",
            "- **Research References**:",
            "  1. *NIST SP 800-77 Rev. 1: Guide to IPsec VPNs* (https://csrc.nist.gov/pubs/sp/800/77/r1/final)",
            "  2. *Fesl & Naas: A comprehensive machine learning-based approach for virtual private network traffic detection* (Computer Networks, 2025)",
            "  3. *Luo, Chu & Yang: IP packet-level encrypted traffic classification using machine learning* (JISA, 2023)",
            "  4. *Roy, Shapira & Shavitt: Fast and lean encrypted Internet traffic classification* (Computer Communications, 2022)"
        ])

        return "\n".join(lines)

    def generate_executive_summary_markdown(self, analysis: AnalysisResult) -> str:
        asm = analysis.security_assessment
        lines = [
            f"# IPsecAI Executive Security Summary",
            f"**Session**: `{analysis.ipsec_session.session_id}` | **Assessed**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            "",
            f"### Security Posture: **{asm.overall_score} / 100** ({asm.risk_level} Risk)",
            "",
            f"> {asm.summary}",
            "",
            "#### Key Findings Summary",
            "| Severity | Finding Title | Recommended Action |",
            "| :--- | :--- | :--- |"
        ]

        if not asm.findings:
            lines.append("| Info | Compliant Configuration | Maintain regular audit schedule |")
        else:
            for f in asm.findings:
                lines.append(f"| **{f.severity}** | {f.title} | {f.recommendation} |")

        lines.extend([
            "",
            "#### Strategic Actions",
            "1. **Enforce Modern AEAD**: Ensure all child SAs utilize AES-256-GCM or ChaCha20-Poly1305.",
            "2. **Enable PFS**: Mandate Diffie-Hellman Group 14 or Group 19 on all Phase 2 / Child SAs.",
            "3. **Validate Anti-Replay Windows**: Verify replay protection sliding windows (min 64 packets) are active across all IPsec terminations.",
            "",
            "*Confidential — Generated by IPsecAI Prototype Framework.*"
        ])
        return "\n".join(lines)

    def generate_json_export(self, analysis: AnalysisResult) -> str:
        return analysis.model_dump_json(indent=2)

    def generate_findings_csv(self, analysis: AnalysisResult) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "finding_id", "rule_id", "severity", "category",
            "title", "evidence", "impact", "recommendation",
            "reference", "likelihood", "impact_level", "status"
        ])

        for f in analysis.security_assessment.findings:
            writer.writerow([
                f.id, f.rule_id, f.severity, f.category,
                f.title, f.evidence, f.impact, f.recommendation,
                f.reference, f.likelihood, f.impact_level, f.status
            ])

        return output.getvalue()

    def generate_html_report(self, analysis: AnalysisResult) -> str:
        md = self.generate_technical_report_markdown(analysis)
        # Convert to clean styled HTML document
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IPsecAI Security Report - {analysis.analysis_id}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #f8fafc;
            color: #0f172a;
            line-height: 1.6;
            margin: 0;
            padding: 40px;
        }}
        .container {{
            max-width: 960px;
            margin: 0 auto;
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 4px;
            padding: 40px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        h1, h2, h3, h4 {{
            color: #0f172a;
            border-bottom: 1px solid #e2e8f0;
            padding-bottom: 8px;
        }}
        h1 {{ font-size: 24px; }}
        h2 {{ font-size: 18px; margin-top: 24px; }}
        h3 {{ font-size: 15px; margin-top: 16px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 16px 0;
            font-size: 14px;
        }}
        th, td {{
            text-align: left;
            padding: 10px 12px;
            border-bottom: 1px solid #e2e8f0;
        }}
        th {{
            background-color: #f1f5f9;
            font-weight: 600;
        }}
        code {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            background: #f1f5f9;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 13px;
        }}
        blockquote {{
            background: #f8fafc;
            border-left: 4px solid #2563eb;
            margin: 16px 0;
            padding: 12px 16px;
            color: #334155;
        }}
        .badge-score {{
            display: inline-block;
            background: #2563eb;
            color: #ffffff;
            padding: 6px 14px;
            border-radius: 4px;
            font-weight: 600;
            font-size: 16px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #0f172a; padding-bottom: 16px; margin-bottom: 24px;">
            <div>
                <h1 style="border: none; margin: 0;">IPsecAI Technical Security Report</h1>
                <p style="margin: 4px 0 0 0; color: #64748b; font-size: 14px;">AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework</p>
            </div>
            <div class="badge-score">{analysis.security_assessment.overall_score} / 100 ({analysis.security_assessment.risk_level} Risk)</div>
        </div>
        
        <h2>1. Executive Summary</h2>
        <p>{analysis.security_assessment.summary}</p>

        <h2>2. Capture Summary</h2>
        <table>
            <tr><th>Filename</th><td><code>{analysis.capture_summary.filename}</code></td><th>Source</th><td>{analysis.capture_summary.source_type}</td></tr>
            <tr><th>Packets</th><td>{analysis.capture_summary.packet_count:,}</td><th>Total Bytes</th><td>{analysis.capture_summary.byte_count:,} bytes</td></tr>
            <tr><th>Source Endpoint</th><td><code>{analysis.ipsec_session.src_endpoint}</code></td><th>Destination Endpoint</th><td><code>{analysis.ipsec_session.dst_endpoint}</code></td></tr>
            <tr><th>Observed Protocols</th><td colspan="3">{", ".join(analysis.capture_summary.protocols_observed)}</td></tr>
        </table>

        <h2>3. Observed Protocol & Security Parameters</h2>
        <table>
            <thead><tr><th>Parameter</th><th>Value</th><th>Source</th><th>Notes</th></tr></thead>
            <tbody>
                {''.join([f"<tr><td><strong>{p.parameter}</strong></td><td><code>{p.value}</code></td><td>{p.source}</td><td>{p.notes or ''}</td></tr>" for p in analysis.observed_parameters])}
            </tbody>
        </table>

        <h2>4. Identified Findings ({len(analysis.security_assessment.findings)})</h2>
        {''.join([f"<div style='margin-bottom: 16px; border: 1px solid #e2e8f0; padding: 14px; border-radius: 4px; background: #ffffff;'><strong>[{f.severity}] {f.title}</strong> (<code>{f.rule_id}</code>)<br><span style='color: #475569;'>Category: {f.category} | Reference: {f.reference}</span><p style='margin: 6px 0;'><strong>Evidence:</strong> {f.evidence}</p><p style='margin: 6px 0;'><strong>Impact:</strong> {f.impact}</p><p style='margin: 6px 0; color: #1e40af;'><strong>Recommendation:</strong> {f.recommendation}</p></div>" for f in analysis.security_assessment.findings]) if analysis.security_assessment.findings else "<p>No security weaknesses detected.</p>"}

        <h2>5. Encrypted Traffic Inferences (Observable Metadata)</h2>
        <table>
            <thead><tr><th>Flow ID</th><th>Protocol</th><th>Volume</th><th>Inferred Type</th><th>Confidence</th></tr></thead>
            <tbody>
                {''.join([f"<tr><td><code>{c.flow_id}</code></td><td>ESP</td><td>{f.packet_count} pkts ({f.byte_count:,} B)</td><td><strong>{c.predicted_class}</strong></td><td>{int(c.confidence_score*100)}%</td></tr>" for c, f in zip(analysis.traffic_classifications, analysis.flows)])}
            </tbody>
        </table>

        <div style="margin-top: 32px; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 12px;">
            Confidential — IPsecAI Prototype Framework — Research grounded in NIST SP 800-77 Rev. 1
        </div>
    </div>
</body>
</html>"""
        return html
