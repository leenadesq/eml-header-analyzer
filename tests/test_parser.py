"""Tests for eml_header_analyzer.parser."""

from __future__ import annotations

import os

from eml_header_analyzer.parser import parse_eml


FIXTURE = os.path.join(os.path.dirname(__file__), "data", "sample1.eml")


def test_message_envelope_fields():
    report = parse_eml(FIXTURE)
    assert report.message_id == "<20250514101530.ABCDEF@example.com>"
    assert "alice@example.com" in report.from_addr
    assert any("bob@recipient.example.org" in a for a in report.to_addrs)
    assert report.subject == "Test message for eml-header-analyzer"


def test_received_chain_is_parsed():
    report = parse_eml(FIXTURE)
    assert len(report.hops) == 2
    top = report.hops[0]
    assert "out.example.com" in top.from_host
    assert top.with_protocol.lower().startswith("esmtps")


def test_authentication_results_split():
    report = parse_eml(FIXTURE)
    assert report.spf.startswith("spf=pass")
    assert report.dkim.startswith("dkim=pass")
    assert report.dmarc.startswith("dmarc=pass")


def test_originating_ip_and_mailer():
    report = parse_eml(FIXTURE)
    assert "198.51.100.42" in report.originating_ip
    assert "TestMailer" in report.mailer


def test_no_false_warnings_on_clean_fixture():
    report = parse_eml(FIXTURE)
    # Authentication is present, so the "no auth" warning should not fire.
    assert all("No Authentication-Results" not in w for w in report.warnings)
