# ==============================================================================
# Product:       lh-abuse-sentinel (lh-abuse)
# Module:        src.lh_abuse_sentinel.abuse_analyzer
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Abuse sentinel analysis engine and rate-limiting inspection rules."""

from __future__ import annotations

import re
from pathlib import Path

from lh_abuse_sentinel.models import (
    RULES_REGISTRY,
    AuditFinding,
    AuditReport,
    FindingSeverity,
    RateLimitPolicy,
    RequestVelocityEvent,
)
from lh_abuse_sentinel.throttle_parser import find_throttle_files, parse_throttle_file

SENSITIVE_AUTH_ROUTES = (
    "/login",
    "/auth",
    "/token",
    "/password-reset",
    "/password",
    "/otp",
    "/register",
    "/checkout",
    "/signin",
)

PUBLIC_FORM_ROUTES = (
    "/register",
    "/signup",
    "/password-reset",
    "/contact",
    "/forgot-password",
)

COMPLEXITY_SENSITIVE_ROUTES = (
    "/graphql",
    "/search",
    "/export",
    "/bulk",
    "/query",
)


class AbuseAnalyzer:
    """Core evaluation engine analyzing rate-limiting rules and velocity anomalies."""

    def __init__(self, policies: list[RateLimitPolicy], events: list[RequestVelocityEvent]) -> None:
        self.policies = policies
        self.events = events

    def analyze(self) -> list[AuditFinding]:
        """Execute complete suite of 10 abuse detection rules."""
        findings: list[AuditFinding] = []

        findings.extend(self._check_lh_abu_001())
        findings.extend(self._check_lh_abu_002())
        findings.extend(self._check_lh_abu_003())
        findings.extend(self._check_lh_abu_004())
        findings.extend(self._check_lh_abu_005())
        findings.extend(self._check_lh_abu_006())
        findings.extend(self._check_lh_abu_007())
        findings.extend(self._check_lh_abu_008())
        findings.extend(self._check_lh_abu_009())
        findings.extend(self._check_lh_abu_010())

        return findings

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

    def _check_lh_abu_001(self) -> list[AuditFinding]:
        """LH-ABU-001 (CRITICAL): Missing Rate-Limiting on Authentication Endpoint."""
        rule = RULES_REGISTRY["LH-ABU-001"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            route_lower = p.target_route.lower()
            is_sensitive = any(s in route_lower for s in SENSITIVE_AUTH_ROUTES)

            disabled = p.rate_limit_enabled is False
            no_quota = p.rate_limit_enabled is None and (
                p.requests_per_minute is None or p.requests_per_minute == 0
            )

            if is_sensitive and (disabled or no_quota):
                evidence = (
                    f"Route '{p.target_route}' has rate_limit_enabled={p.rate_limit_enabled}, "
                    f"requests_per_minute={p.requests_per_minute}"
                )
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_route})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Sensitive endpoint '{p.target_route}' lacks active rate limiting or "
                            f"configured request quotas."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )
        return findings

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

    def _check_lh_abu_002(self) -> list[AuditFinding]:
        """LH-ABU-002 (CRITICAL): Spoofable Rate-Limit Key (Unvalidated Header Trust)."""
        rule = RULES_REGISTRY["LH-ABU-002"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            key_lower = p.key_by.lower()
            is_header_key = any(
                h in key_lower for h in ["x_forwarded_for", "x-forwarded-for", "real_ip"]
            )

            unvalidated_proxy = p.trust_any_proxy is True or len(p.trusted_proxies) == 0

            if is_header_key and unvalidated_proxy:
                evidence = (
                    f"Keyed by '{p.key_by}' with trust_any_proxy={p.trust_any_proxy}, "
                    f"trusted_proxies={p.trusted_proxies}"
                )
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_route})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Rate limiter for route '{p.target_route}' uses spoofable client "
                            f"header '{p.key_by}' without validating trusted proxy CIDRs."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )
        return findings

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

    def _check_lh_abu_003(self) -> list[AuditFinding]:
        """LH-ABU-003 (HIGH): Missing Account Lockout or Progressive Backoff."""
        rule = RULES_REGISTRY["LH-ABU-003"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            route_lower = p.target_route.lower()
            is_auth_route = any(s in route_lower for s in SENSITIVE_AUTH_ROUTES)

            missing_lockout = p.lockout_enabled is False or p.max_failed_attempts == 0
            missing_backoff = p.exponential_backoff is False

            if is_auth_route and (missing_lockout or missing_backoff):
                ev_items: list[str] = []
                if missing_lockout:
                    ev_items.append(
                        f"lockout_enabled={p.lockout_enabled}, "
                        f"max_failed_attempts={p.max_failed_attempts}"
                    )
                if missing_backoff:
                    ev_items.append("exponential_backoff=False")

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_route})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Authentication policy for route '{p.target_route}' lacks account "
                            f"lockout thresholds or progressive backoff delays."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )
        return findings

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

    def _check_lh_abu_004(self) -> list[AuditFinding]:
        """LH-ABU-004 (HIGH): Permissive Rate-Limit Threshold Vulnerable to Brute-Force."""
        rule = RULES_REGISTRY["LH-ABU-004"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            route_lower = p.target_route.lower()
            is_sensitive = any(s in route_lower for s in SENSITIVE_AUTH_ROUTES)

            excessive_rpm = p.requests_per_minute is not None and p.requests_per_minute > 30
            excessive_burst = p.burst_size is not None and p.burst_size > 100

            if is_sensitive and (excessive_rpm or excessive_burst):
                ev_items: list[str] = []
                if excessive_rpm:
                    ev_items.append(f"requests_per_minute={p.requests_per_minute} (> 30 RPM limit)")
                if excessive_burst:
                    ev_items.append(f"burst_size={p.burst_size} (> 100 threshold)")

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_route})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Configured rate limit on sensitive route '{p.target_route}' is "
                            f"overly permissive and susceptible to brute-force attacks."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )
        return findings

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

    def _check_lh_abu_005(self) -> list[AuditFinding]:
        """LH-ABU-005 (HIGH): Missing Connection Limit or Slowloris Timeout Defense."""
        rule = RULES_REGISTRY["LH-ABU-005"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            missing_conn = (
                p.max_concurrent_connections is not None and p.max_concurrent_connections == 0
            )
            slow_hdr = (
                p.client_header_timeout_seconds is not None and p.client_header_timeout_seconds > 60
            )
            slow_body = (
                p.client_body_timeout_seconds is not None and p.client_body_timeout_seconds > 60
            )

            if missing_conn or slow_hdr or slow_body:
                ev_items: list[str] = []
                if missing_conn:
                    ev_items.append("max_concurrent_connections=0 (unlimited)")
                if slow_hdr:
                    ev_items.append(
                        f"client_header_timeout={p.client_header_timeout_seconds}s (> 60s)"
                    )
                if slow_body:
                    ev_items.append(f"client_body_timeout={p.client_body_timeout_seconds}s (> 60s)")

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_route})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Server configuration for route '{p.target_route}' lacks concurrent "
                            f"connection caps or permits excessive read timeouts."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )
        return findings

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

    def _check_lh_abu_006(self) -> list[AuditFinding]:
        """LH-ABU-006 (HIGH): Distributed Brute-Force or Enumeration Velocity Anomaly."""
        rule = RULES_REGISTRY["LH-ABU-006"]
        findings: list[AuditFinding] = []

        # Check per-IP failure bursts
        ip_failures: dict[str, list[RequestVelocityEvent]] = {}
        route_failures: dict[str, list[RequestVelocityEvent]] = {}

        for ev in self.events:
            if ev.status_code in [401, 403, 404, 429]:
                ip_failures.setdefault(ev.client_ip, []).append(ev)
                route_failures.setdefault(ev.route, []).append(ev)

        for ip, fails in ip_failures.items():
            if len(fails) >= 5:
                sample_routes = ", ".join({f.route for f in fails[:3]})
                evidence = (
                    f"IP {ip} produced {len(fails)} error responses (401/403/404/429) "
                    f"targeting: {sample_routes}"
                )
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"ip:{ip}",
                        title=f"{rule.title} - Burst from {ip}",
                        description=(
                            f"High-frequency failed response burst ({len(fails)} events) "
                            f"detected from client IP {ip}."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )

        # Check distributed attacks targeting same sensitive route across multiple IPs
        for route, fails in route_failures.items():
            distinct_ips = {f.client_ip for f in fails if f.client_ip}
            is_sensitive = any(s in route.lower() for s in SENSITIVE_AUTH_ROUTES)
            if is_sensitive and len(distinct_ips) >= 3 and len(fails) >= 5:
                evidence = (
                    f"Route '{route}' targeted by {len(distinct_ips)} distinct IPs with "
                    f"{len(fails)} failure events"
                )
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"route:{route}",
                        title=f"{rule.title} - Distributed Attack on {route}",
                        description=(
                            f"Distributed credential stuffing or brute-force pattern targeting "
                            f"sensitive route '{route}'."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )

        # Check sequential identifier enumeration in routes
        id_pattern = re.compile(r"/([0-9]{3,})(/|$)")
        enumerated_routes: dict[str, list[str]] = {}
        for ev in self.events:
            m = id_pattern.search(ev.route)
            if m:
                base = id_pattern.sub("/:id\\2", ev.route)
                enumerated_routes.setdefault(base, []).append(ev.route)

        for base_route, probe_list in enumerated_routes.items():
            if len(probe_list) >= 3:
                evidence = f"Sequential ID queries: {', '.join(probe_list[:3])}"
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"route:{base_route}",
                        title=f"{rule.title} - Enumeration on {base_route}",
                        description=(
                            f"Sequential numeric resource enumeration sweep detected on "
                            f"endpoint '{base_route}'."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )

        return findings

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

    def _check_lh_abu_007(self) -> list[AuditFinding]:
        """LH-ABU-007 (MEDIUM): Missing Bot Challenge, Proof-of-Work, or CAPTCHA Step-Up."""
        rule = RULES_REGISTRY["LH-ABU-007"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            route_lower = p.target_route.lower()
            is_public_form = any(pf in route_lower for pf in PUBLIC_FORM_ROUTES)

            missing_challenge = is_public_form and (p.challenge_enabled is False)

            if missing_challenge:
                evidence = (
                    f"challenge_enabled={p.challenge_enabled} on public route '{p.target_route}'"
                )
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_route})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Public submission endpoint '{p.target_route}' lacks bot challenge, "
                            f"proof-of-work, or CAPTCHA mitigation."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )
        return findings

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

    def _check_lh_abu_008(self) -> list[AuditFinding]:
        """LH-ABU-008 (HIGH): Fail-Open Rate-Limiter Store or Missing Window TTL."""
        rule = RULES_REGISTRY["LH-ABU-008"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            is_fail_open = p.fail_open is True
            fixed_window = p.algorithm == "fixed_window"
            missing_ttl = p.algorithm != "" and (p.ttl_seconds is not None and p.ttl_seconds == 0)

            if is_fail_open or fixed_window or missing_ttl:
                ev_items: list[str] = []
                if is_fail_open:
                    ev_items.append("fail_open=True (bypasses rate limit on backend error)")
                if fixed_window:
                    ev_items.append("algorithm='fixed_window' (boundary burst vulnerability)")
                if missing_ttl:
                    ev_items.append("ttl_seconds=0 (missing key expiration)")

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_route})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Rate limiter for route '{p.target_route}' has architectural "
                            f"resilience flaws allowing traffic surges during store failures or "
                            f"window boundaries."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )
        return findings

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

    def _check_lh_abu_009(self) -> list[AuditFinding]:
        """LH-ABU-009 (MEDIUM): Missing Payload Cost / GraphQL Query Complexity Budget."""
        rule = RULES_REGISTRY["LH-ABU-009"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            route_lower = p.target_route.lower()
            is_heavy_route = any(c in route_lower for c in COMPLEXITY_SENSITIVE_ROUTES)

            no_complexity = p.max_query_complexity is None or p.max_query_complexity == 0
            no_depth = p.max_query_depth is None or p.max_query_depth == 0

            if is_heavy_route and (no_complexity or no_depth):
                evidence = (
                    f"max_query_complexity={p.max_query_complexity}, "
                    f"max_query_depth={p.max_query_depth}"
                )
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_route})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Compute-intensive route '{p.target_route}' does not enforce query "
                            f"complexity budgets or maximum query depth limits."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )
        return findings

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

    def _check_lh_abu_010(self) -> list[AuditFinding]:
        """LH-ABU-010 (LOW): Missing Standard Rate-Limit Telemetry Headers or Retry-After."""
        rule = RULES_REGISTRY["LH-ABU-010"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            missing_hdrs = p.send_headers is False
            missing_retry = p.include_retry_after is False
            missing_audit = p.audit_logging is False

            if missing_hdrs or missing_retry or missing_audit:
                ev_items: list[str] = []
                if missing_hdrs:
                    ev_items.append("send_headers=False")
                if missing_retry:
                    ev_items.append("include_retry_after=False")
                if missing_audit:
                    ev_items.append("audit_logging=False")

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_route})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Rate-limiting policy for route '{p.target_route}' omits standard "
                            f"IETF telemetry headers or 429 decision audit logs."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )
        return findings


def calculate_risk_score(findings: list[AuditFinding]) -> int:
    """Calculate consolidated abuse risk score from findings (0-100)."""
    if not findings:
        return 0

    crit = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    hi = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
    med = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
    lo = sum(1 for f in findings if f.severity == FindingSeverity.LOW)

    raw_score = crit * 25 + hi * 15 + med * 5 + lo * 2
    return min(100, raw_score)


def audit_abuse_target(target: Path) -> AuditReport:
    """Ingest rate-limiting definitions and evaluate against complete rule catalog."""
    files = find_throttle_files(target)

    all_policies: list[RateLimitPolicy] = []
    all_events: list[RequestVelocityEvent] = []

    for f in files:
        policies, events = parse_throttle_file(f)
        all_policies.extend(policies)
        all_events.extend(events)

    analyzer = AbuseAnalyzer(all_policies, all_events)
    findings = analyzer.analyze()

    crit = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    hi = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
    med = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
    lo = sum(1 for f in findings if f.severity == FindingSeverity.LOW)

    summary = {
        "critical": crit,
        "high": hi,
        "medium": med,
        "low": lo,
    }

    risk_score = calculate_risk_score(findings)

    return AuditReport(
        target=str(target),
        files_scanned=len(files),
        policies_analyzed=len(all_policies),
        velocity_events_analyzed=len(all_events),
        findings_count=len(findings),
        findings=findings,
        summary=summary,
        risk_score=risk_score,
    )
