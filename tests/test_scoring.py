"""
Tests for IPsecAI Scoring Engine
Verifies score range (0-100), transparent deductions, and risk level assignment.
"""

import pytest
from backend.models.schema import IPsecSession, SecurityAssociation
from backend.parsers.synthetic_generator import SyntheticProfileGenerator
from backend.assessment.rule_engine import RuleEngine
from backend.assessment.scoring_engine import ScoringEngine


def test_scoring_demo_a_healthy():
    gen = SyntheticProfileGenerator()
    res = gen.generate_profile("demo_a")
    score = res.security_assessment.overall_score
    assert 85 <= score <= 100, f"Demo A should have a high score, got {score}"
    assert res.security_assessment.risk_level in ["Low", "Medium"]
    assert res.security_assessment.score_breakdown.base_score == 100


def test_scoring_demo_b_weak():
    gen = SyntheticProfileGenerator()
    res = gen.generate_profile("demo_b")
    score = res.security_assessment.overall_score
    assert 0 <= score <= 60, f"Demo B should have a low/critical score, got {score}"
    assert res.security_assessment.risk_level in ["High", "Critical"]
    assert len(res.security_assessment.findings) >= 4


def test_scoring_bounds():
    rule_engine = RuleEngine()
    scoring_engine = ScoringEngine()

    # Extremely broken session
    sa = SecurityAssociation(
        spi_in="0x0",
        spi_out="0x0",
        protocol="ESP",
        mode="Transport",
        encryption_algorithm="DES",
        integrity_algorithm="MD5",
        dh_group="Group 1",
        pfs_enabled=False,
        replay_protection_enabled=False,
        replay_window_size=0,
        sa_lifetime_seconds=999999,
        sa_volume_limit_mb=999999,
        metadata_padding_enabled=False
    )
    session = IPsecSession(
        session_id="TEST-CRITICAL",
        src_endpoint="1.1.1.1",
        dst_endpoint="2.2.2.2",
        vpn_mode="Transport",
        ike_version="IKEv1",
        security_association=sa
    )

    findings = rule_engine.evaluate_session(session)
    assessment = scoring_engine.assess(session, findings)

    assert 0 <= assessment.overall_score <= 100, "Score must be bounded between 0 and 100"
    assert assessment.risk_level == "Critical"
