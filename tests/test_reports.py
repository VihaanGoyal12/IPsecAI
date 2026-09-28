"""
Tests for Testbed Generator and Report Generator
"""

import pytest
from backend.models.schema import TestbedRequest
from backend.testbed.testbed_generator import TestbedGenerator
from backend.parsers.synthetic_generator import SyntheticProfileGenerator
from backend.reporting.report_generator import ReportGenerator


def test_testbed_profile_generation():
    generator = TestbedGenerator()
    req = TestbedRequest(
        vpn_mode="Tunnel",
        encryption_algorithm="AES-256-GCM",
        dh_group="Group 14",
        pfs_enabled=True,
        replay_protection=True,
        ip_version="IPv4",
        traffic_type="Video",
        lifetime_hours=8
    )

    profile = generator.generate_test_profile(req)
    assert profile.profile_id.startswith("TB-")
    assert 0 <= profile.expected_security_score <= 100
    assert "charondebug" in profile.strongswan_conf
    assert "connections" in profile.swanctl_conf
    assert profile.disclaimer is not None


def test_reports_generation():
    syn_gen = SyntheticProfileGenerator()
    analysis = syn_gen.generate_profile("demo_a")
    rep_gen = ReportGenerator()

    # Technical report
    tech_md = rep_gen.generate_technical_report_markdown(analysis)
    assert "# IPsecAI Technical Security Assessment Report" in tech_md
    assert "NIST SP 800-77" in tech_md

    # Executive report
    exec_md = rep_gen.generate_executive_summary_markdown(analysis)
    assert "Executive Security Summary" in exec_md

    # HTML report
    html = rep_gen.generate_html_report(analysis)
    assert "<!DOCTYPE html>" in html
    assert "IPsecAI" in html

    # JSON & CSV
    json_str = rep_gen.generate_json_export(analysis)
    assert "analysis_id" in json_str

    csv_str = rep_gen.generate_findings_csv(analysis)
    assert "finding_id" in csv_str
