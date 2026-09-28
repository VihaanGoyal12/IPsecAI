"""
Tests for IPsecAI Rule Engine
Verifies deterministic rule evaluation against healthy and weak IPsec sessions.
"""

import pytest
from backend.models.schema import IPsecSession, SecurityAssociation, IKEExchange
from backend.assessment.rule_engine import RuleEngine


def test_rule_engine_loads_rules():
    engine = RuleEngine()
    assert len(engine.rules) > 0, "Rule engine should load security rules from yaml"


def test_rule_engine_healthy_profile():
    engine = RuleEngine()
    sa = SecurityAssociation(
        spi_in="0x12345678",
        spi_out="0x87654321",
        protocol="ESP",
        mode="Tunnel",
        encryption_algorithm="AES-256-GCM",
        integrity_algorithm="AEAD (Built-in)",
        dh_group="Group 19",
        pfs_enabled=True,
        replay_protection_enabled=True,
        replay_window_size=128,
        sa_lifetime_seconds=28800,
        sa_volume_limit_mb=4096,
        metadata_padding_enabled=True,
        ip_version="IPv4"
    )
    session = IPsecSession(
        session_id="TEST-HEALTHY",
        src_endpoint="198.51.100.1",
        dst_endpoint="203.0.113.1",
        vpn_mode="Tunnel",
        ipsec_protocol="ESP",
        ike_version="IKEv2",
        security_association=sa
    )

    findings = engine.evaluate_session(session)
    # Healthy configuration should have 0 or minimal low-severity notices
    high_findings = [f for f in findings if f.severity == "High"]
    assert len(high_findings) == 0, f"Healthy profile should not produce High severity findings: {high_findings}"


def test_rule_engine_weak_profile():
    engine = RuleEngine()
    sa = SecurityAssociation(
        spi_in="0x11111111",
        spi_out="0x22222222",
        protocol="ESP",
        mode="Transport",
        encryption_algorithm="3DES-CBC",
        integrity_algorithm="MD5",
        dh_group="Group 2",
        pfs_enabled=False,
        replay_protection_enabled=False,
        replay_window_size=0,
        sa_lifetime_seconds=172800,
        sa_volume_limit_mb=50000,
        metadata_padding_enabled=False,
        ip_version="IPv4"
    )
    session = IPsecSession(
        session_id="TEST-WEAK",
        src_endpoint="192.0.2.1",
        dst_endpoint="198.51.100.2",
        vpn_mode="Transport",
        ipsec_protocol="ESP",
        ike_version="IKEv1",
        security_association=sa
    )

    findings = engine.evaluate_session(session)
    rule_ids = [f.rule_id for f in findings]
    assert "IPSEC-CRYPTO-001" in rule_ids, "Should trigger legacy cipher rule"
    assert "IPSEC-AUTH-001" in rule_ids, "Should trigger MD5 rule"
    assert "IPSEC-PFS-001" in rule_ids, "Should trigger PFS disabled rule"
    assert "IPSEC-REPLAY-001" in rule_ids, "Should trigger replay protection rule"
    assert "IPSEC-MODE-001" in rule_ids, "Should trigger transport mode rule"
