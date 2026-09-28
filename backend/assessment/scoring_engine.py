"""
IPsecAI Scoring Engine
Calculates transparent heuristic security score (0-100) and risk posture from rule findings and session state.
"""

from typing import List, Dict, Any
from backend.models.schema import (
    IPsecSession,
    Finding,
    SecurityAssessment,
    SecurityScoreBreakdown,
    CategoryAssessment,
)


class ScoringEngine:
    def __init__(self):
        self.category_weights = {
            "Cryptography": 25,
            "Authentication": 20,
            "Key Exchange": 20,
            "PFS": 15,
            "Replay Protection": 15,
            "SA Lifetime": 10,
            "Configuration": 15,
            "Metadata Exposure": 5,
        }

    def assess(self, session: IPsecSession, findings: List[Finding]) -> SecurityAssessment:
        base_score = 100
        deductions: List[Dict[str, Any]] = []
        total_deduction = 0

        # Severity penalties mapping if not specified in finding
        severity_penalty = {
            "High": 15,
            "Medium": 8,
            "Low": 3,
            "Informational": 0,
        }

        # Calculate deductions from findings
        category_penalties: Dict[str, int] = {cat: 0 for cat in self.category_weights}

        for finding in findings:
            penalty = severity_penalty.get(finding.severity, 5)
            # Custom adjustments
            if "Insecure Cipher" in finding.title or "3DES" in finding.title:
                penalty = 25
            elif "Insecure Integrity" in finding.title or "MD5" in finding.title:
                penalty = 20
            elif "Deprecated Diffie-Hellman" in finding.title:
                penalty = 20
            elif "PFS Disabled" in finding.title:
                penalty = 15
            elif "Anti-Replay Protection Disabled" in finding.title:
                penalty = 15
            elif "Transport Mode" in finding.title:
                penalty = 10
            elif "Legacy IKEv1" in finding.title:
                penalty = 12
            elif "Excessive SA Lifetime" in finding.title:
                penalty = 8
            elif "Acceptable Standard DH Group" in finding.title:
                penalty = 2

            total_deduction += penalty
            cat = finding.category if finding.category in category_penalties else "Configuration"
            category_penalties[cat] = category_penalties.get(cat, 0) + penalty

            deductions.append({
                "rule_id": finding.rule_id,
                "title": finding.title,
                "category": finding.category,
                "severity": finding.severity,
                "penalty": penalty,
                "reason": finding.evidence
            })

        final_score = max(0, min(100, base_score - total_deduction))

        # Determine overall risk level
        if final_score >= 85:
            risk_level = "Low"
        elif final_score >= 70:
            risk_level = "Medium"
        elif final_score >= 50:
            risk_level = "High"
        else:
            risk_level = "Critical"

        # Build Category Assessments (Pass / Review / Concern)
        categories: List[CategoryAssessment] = []
        sa = session.security_association

        category_details = {
            "Cryptography": f"Algorithm: {sa.encryption_algorithm}",
            "Authentication": f"Integrity: {sa.integrity_algorithm}",
            "Key Exchange": f"DH Group: {sa.dh_group}",
            "PFS": f"Status: {'Enabled' if sa.pfs_enabled else 'Disabled'}",
            "Replay Protection": f"Status: {'Enabled (Window: ' + str(sa.replay_window_size) + ')' if sa.replay_protection_enabled else 'Disabled'}",
            "SA Lifetime": f"Lifetime: {sa.sa_lifetime_seconds}s, Volume: {sa.sa_volume_limit_mb}MB",
            "Configuration": f"Mode: {session.vpn_mode}, Protocol: {session.ike_version}",
            "Metadata Exposure": f"TFC Padding: {'Enabled' if sa.metadata_padding_enabled else 'Disabled'}"
        }

        for cat, details in category_details.items():
            pen = category_penalties.get(cat, 0)
            if pen == 0:
                result = "Pass"
            elif pen <= 8:
                result = "Review"
            else:
                result = "Concern"

            categories.append(CategoryAssessment(
                category=cat,
                result=result,
                score_contribution=-pen,
                details=details
            ))

        # Generate concise summary
        if final_score >= 85:
            summary = (
                f"Overall security posture is robust with a score of {final_score}/100 ({risk_level} Risk). "
                f"Modern cryptographic primitives and defensive measures (e.g., AEAD ciphers, PFS, replay protection) are correctly configured."
            )
        elif final_score >= 70:
            summary = (
                f"Overall security posture is acceptable with a score of {final_score}/100 ({risk_level} Risk). "
                f"A few configuration weaknesses were identified (e.g. non-PFS keying or CBC legacy mode) that should be reviewed."
            )
        elif final_score >= 50:
            summary = (
                f"Security assessment indicates elevated risk with a score of {final_score}/100 ({risk_level} Risk). "
                f"{len(findings)} configuration findings require immediate administrative review to mitigate exposure."
            )
        else:
            summary = (
                f"Critical security risks identified with a score of {final_score}/100 ({risk_level} Risk). "
                f"Deprecated ciphers, disabled replay protection, or insecure key exchange parameters leave this IPsec tunnel vulnerable."
            )

        score_breakdown = SecurityScoreBreakdown(
            base_score=base_score,
            total_deductions=total_deduction,
            final_score=final_score,
            risk_level=risk_level,
            deductions=deductions,
            methodology="Heuristic weighted deduction grounded in NIST SP 800-77 Rev. 1 guidelines."
        )

        return SecurityAssessment(
            assessment_id=f"ASM-{session.session_id}",
            overall_score=final_score,
            risk_level=risk_level,
            summary=summary,
            categories=categories,
            score_breakdown=score_breakdown,
            findings=findings,
            total_findings=len(findings)
        )
