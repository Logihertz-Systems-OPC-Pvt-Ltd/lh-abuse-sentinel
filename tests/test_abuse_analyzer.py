# ==============================================================================
# Product:       lh-abuse-sentinel (lh-abuse)
# Module:        tests.test_abuse_analyzer
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Tests for abuse_analyzer module and detection rules (LH-ABU-001 through LH-ABU-010)."""

from __future__ import annotations

from pathlib import Path

from lh_abuse_sentinel.abuse_analyzer import (
    AbuseAnalyzer,
    audit_abuse_target,
    calculate_risk_score,
)
from lh_abuse_sentinel.models import (
    AuditFinding,
    FindingSeverity,
    RateLimitPolicy,
)


def test_clean_policies_produce_no_findings(sample_clean_yaml: Path) -> None:
    """Test that a strictly configured policy produces zero findings."""
    report = audit_abuse_target(sample_clean_yaml)
    assert report.findings_count == 0
    assert len(report.findings) == 0
    assert report.risk_score == 0
    assert report.policies_analyzed == 1
    # --------------------------------------------------------------------------
    # --- Rule LH-ABU-001 (CRITICAL):
    #     Missing Rate-Limiting on Authentication or Sensitive Endpoint
    # ---
    # Evaluates security posture against missing rate-limiting on authentication or
    # sensitive endpoint.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_abu_001_missing_rate_limiting() -> None:
    """Test LH-ABU-001: Missing rate limiting on sensitive auth route."""
    pol = RateLimitPolicy(
        policy_id="p-01",
        name="Auth Login Policy",
        target_route="/login",
        rate_limit_enabled=False,
    )
    analyzer = AbuseAnalyzer([pol], [])
    findings = analyzer._check_lh_abu_001()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-ABU-001"
    assert findings[0].severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-ABU-002 (CRITICAL):
    #     Spoofable Rate-Limit Key (Unvalidated Header Trust)
    # ---
    # Evaluates security posture against spoofable rate-limit key (unvalidated
    # header trust).
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_abu_002_spoofable_key() -> None:
    """Test LH-ABU-002: Rate limiter keyed on X-Forwarded-For with empty trusted proxies."""
    pol = RateLimitPolicy(
        policy_id="p-02",
        name="Header Keyed Policy",
        target_route="/auth/token",
        rate_limit_enabled=True,
        key_by="x-forwarded-for",
        trusted_proxies=[],
        trust_any_proxy=True,
    )
    analyzer = AbuseAnalyzer([pol], [])
    findings = analyzer._check_lh_abu_002()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-ABU-002"
    assert findings[0].severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-ABU-003 (HIGH):
    #     Missing Account Lockout or Progressive Exponential Backoff
    # ---
    # Evaluates security posture against missing account lockout or progressive
    # exponential backoff.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_abu_003_missing_lockout() -> None:
    """Test LH-ABU-003: Auth endpoint missing account lockout or exponential backoff."""
    pol = RateLimitPolicy(
        policy_id="p-03",
        name="No Lockout Auth",
        target_route="/password-reset",
        rate_limit_enabled=True,
        lockout_enabled=False,
        exponential_backoff=False,
    )
    analyzer = AbuseAnalyzer([pol], [])
    findings = analyzer._check_lh_abu_003()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-ABU-003"
    assert findings[0].severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-ABU-004 (HIGH):
    #     Permissive Rate-Limit Threshold Vulnerable to Brute-Force
    # ---
    # Evaluates security posture against permissive rate-limit threshold vulnerable
    # to brute-force.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_abu_004_permissive_thresholds() -> None:
    """Test LH-ABU-004: Excessive RPM (> 30) or burst size (> 100) on auth routes."""
    pol = RateLimitPolicy(
        policy_id="p-04",
        name="Permissive OTP",
        target_route="/otp/verify",
        rate_limit_enabled=True,
        requests_per_minute=60,
        burst_size=200,
    )
    analyzer = AbuseAnalyzer([pol], [])
    findings = analyzer._check_lh_abu_004()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-ABU-004"
    assert findings[0].severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-ABU-005 (HIGH):
    #     Missing Concurrent Connection Limit or Slowloris Timeout Defense
    # ---
    # Evaluates security posture against missing concurrent connection limit or
    # slowloris timeout defense.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_abu_005_connection_limit_and_slowloris() -> None:
    """Test LH-ABU-005: Missing connection limit or excessive read timeout (> 60s)."""
    pol = RateLimitPolicy(
        policy_id="p-05",
        name="Slowloris Gateway",
        target_route="/api/data",
        max_concurrent_connections=0,
        client_header_timeout_seconds=90,
    )
    analyzer = AbuseAnalyzer([pol], [])
    findings = analyzer._check_lh_abu_005()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-ABU-005"
    assert findings[0].severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-ABU-006 (HIGH):
    #     Distributed Brute-Force or Enumeration Velocity Anomaly in Telemetry
    # ---
    # Evaluates security posture against distributed brute-force or enumeration
    # velocity anomaly in telemetry.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_abu_006_velocity_telemetry(sample_velocity_json: Path) -> None:
    """Test LH-ABU-006: High failure bursts, distributed stuffing, and sequential enumeration."""
    report = audit_abuse_target(sample_velocity_json)
    findings = [f for f in report.findings if f.rule_id == "LH-ABU-006"]
    assert len(findings) >= 3  # IP burst, distributed attack, and enumeration
    severities = {f.severity for f in findings}
    assert FindingSeverity.HIGH in severities
    # --------------------------------------------------------------------------
    # --- Rule LH-ABU-007 (MEDIUM):
    #     Missing Bot Challenge, Proof-of-Work, or Turnstile Step-Up
    # ---
    # Evaluates security posture against missing bot challenge, proof-of-work, or
    # turnstile step-up.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_abu_007_missing_bot_challenge() -> None:
    """Test LH-ABU-007: Public registration or form lacking bot challenge."""
    pol = RateLimitPolicy(
        policy_id="p-07",
        name="Unchallenged Form",
        target_route="/register",
        challenge_enabled=False,
    )
    analyzer = AbuseAnalyzer([pol], [])
    findings = analyzer._check_lh_abu_007()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-ABU-007"
    assert findings[0].severity == FindingSeverity.MEDIUM
    # --------------------------------------------------------------------------
    # --- Rule LH-ABU-008 (HIGH):
    #     Fail-Open Rate-Limiter Store or Missing Sliding-Window TTL
    # ---
    # Evaluates security posture against fail-open rate-limiter store or missing
    # sliding-window ttl.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_abu_008_fail_open_and_fixed_window() -> None:
    """Test LH-ABU-008: Fail-open store or fixed-window boundary burst flaw."""
    pol = RateLimitPolicy(
        policy_id="p-08",
        name="Fail Open Cache",
        target_route="/auth/token",
        fail_open=True,
        algorithm="fixed_window",
        ttl_seconds=0,
    )
    analyzer = AbuseAnalyzer([pol], [])
    findings = analyzer._check_lh_abu_008()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-ABU-008"
    assert findings[0].severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-ABU-009 (MEDIUM):
    #     Missing Payload Cost / GraphQL Query Complexity Budget
    # ---
    # Evaluates security posture against missing payload cost / graphql query
    # complexity budget.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_abu_009_missing_complexity_budget() -> None:
    """Test LH-ABU-009: GraphQL or search endpoint lacking query complexity budget."""
    pol = RateLimitPolicy(
        policy_id="p-09",
        name="Unmetered GraphQL",
        target_route="/graphql",
        max_query_complexity=0,
        max_query_depth=0,
    )
    analyzer = AbuseAnalyzer([pol], [])
    findings = analyzer._check_lh_abu_009()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-ABU-009"
    assert findings[0].severity == FindingSeverity.MEDIUM
    # --------------------------------------------------------------------------
    # --- Rule LH-ABU-010 (LOW):
    #     Missing Standard Rate-Limit Telemetry Headers or Retry-After
    # ---
    # Evaluates security posture against missing standard rate-limit telemetry
    # headers or retry-after.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_abu_010_missing_telemetry_headers() -> None:
    """Test LH-ABU-010: Omitting Retry-After, RateLimit headers, or 429 audit logging."""
    pol = RateLimitPolicy(
        policy_id="p-10",
        name="No Header Throttle",
        target_route="/api/export",
        send_headers=False,
        include_retry_after=False,
        audit_logging=False,
    )
    analyzer = AbuseAnalyzer([pol], [])
    findings = analyzer._check_lh_abu_010()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-ABU-010"
    assert findings[0].severity == FindingSeverity.LOW


def test_malicious_yaml_triggers_complete_rule_catalog(sample_malicious_yaml: Path) -> None:
    """Test sample_malicious_yaml triggers expected rules."""
    report = audit_abuse_target(sample_malicious_yaml)
    detected_rules = {f.rule_id for f in report.findings}
    # Should detect LH-ABU-001, 002, 003, 004, 005, 007, 008, 009, 010
    expected = {
        "LH-ABU-001",
        "LH-ABU-002",
        "LH-ABU-003",
        "LH-ABU-004",
        "LH-ABU-005",
        "LH-ABU-007",
        "LH-ABU-008",
        "LH-ABU-009",
        "LH-ABU-010",
    }
    assert expected.issubset(detected_rules)
    assert report.risk_score > 50


def test_calculate_risk_score() -> None:
    """Test calculate_risk_score with various finding severity combinations."""
    assert calculate_risk_score([]) == 0

    findings = [
        AuditFinding(
            rule_id="LH-ABU-001",
            severity=FindingSeverity.CRITICAL,
            category="Test",
            target_resource="res",
            title="T",
            description="D",
            remediation="R",
        ),
        AuditFinding(
            rule_id="LH-ABU-003",
            severity=FindingSeverity.HIGH,
            category="Test",
            target_resource="res",
            title="T",
            description="D",
            remediation="R",
        ),
        AuditFinding(
            rule_id="LH-ABU-007",
            severity=FindingSeverity.MEDIUM,
            category="Test",
            target_resource="res",
            title="T",
            description="D",
            remediation="R",
        ),
        AuditFinding(
            rule_id="LH-ABU-010",
            severity=FindingSeverity.LOW,
            category="Test",
            target_resource="res",
            title="T",
            description="D",
            remediation="R",
        ),
    ]
    # 25 + 15 + 5 + 2 = 47
    assert calculate_risk_score(findings) == 47

    # Cap test at 100
    many_crits = [findings[0]] * 10
    assert calculate_risk_score(many_crits) == 100
