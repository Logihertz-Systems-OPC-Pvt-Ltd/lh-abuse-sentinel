# ==============================================================================
# Product:       lh-abuse-sentinel (lh-abuse)
# Module:        src.lh_abuse_sentinel.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and rule definitions for lh-abuse-sentinel."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class FindingSeverity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity ratings for abuse prevention and rate-limiting audit findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def level(self) -> int:
        """Numeric rank for threshold comparison."""
        ranks = {
            FindingSeverity.CRITICAL: 4,
            FindingSeverity.HIGH: 3,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 1,
        }
        return ranks.get(self, 0)

    @classmethod
    def from_string(cls, val: str) -> FindingSeverity:
        """Convert string to FindingSeverity case-insensitively."""
        normalized = val.strip().upper()
        for member in cls:
            if member.value == normalized:
                return member
        return cls.LOW

    def meets_threshold(self, threshold: FindingSeverity) -> bool:
        """Return True if this severity meets or exceeds threshold."""
        return self.level >= threshold.level


@dataclass
class RateLimitPolicy:
    """Extracted API gateway rate-limiting or reverse-proxy throttling definition."""

    policy_id: str = ""
    name: str = ""
    target_route: str = ""
    rate_limit_enabled: bool | None = None
    requests_per_minute: int | None = None
    burst_size: int | None = None
    key_by: str = ""
    trusted_proxies: list[str] = field(default_factory=list)
    trust_any_proxy: bool | None = None
    lockout_enabled: bool | None = None
    max_failed_attempts: int | None = None
    exponential_backoff: bool | None = None
    max_concurrent_connections: int | None = None
    client_header_timeout_seconds: int | None = None
    client_body_timeout_seconds: int | None = None
    challenge_enabled: bool | None = None
    fail_open: bool | None = None
    algorithm: str = ""
    ttl_seconds: int | None = None
    max_query_complexity: int | None = None
    max_query_depth: int | None = None
    send_headers: bool | None = None
    include_retry_after: bool | None = None
    audit_logging: bool | None = None
    source_file: str = ""
    line_number: int = 0


@dataclass
class RequestVelocityEvent:
    """Telemetry record capturing client request velocity and status code."""

    event_id: str = ""
    timestamp: str = ""
    client_ip: str = ""
    route: str = ""
    status_code: int = 200
    user_identifier: str = ""
    source_file: str = ""
    line_number: int = 0


@dataclass
class AuditFinding:
    """Security finding or rate-limiting / brute-force vulnerability."""

    rule_id: str
    severity: FindingSeverity
    category: str
    target_resource: str
    title: str
    description: str
    remediation: str
    evidence: str = ""


@dataclass
class AuditReport:
    """Consolidated rate-limiting and abuse sentinel audit report."""

    target: str
    files_scanned: int = 0
    policies_analyzed: int = 0
    velocity_events_analyzed: int = 0
    findings_count: int = 0
    findings: list[AuditFinding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    risk_score: int = 0


@dataclass(frozen=True)
class AuditRuleDefinition:
    """Static metadata for abuse sentinel audit rules."""

    rule_id: str
    title: str
    severity: FindingSeverity
    category: str
    description: str
    remediation: str


RULES_REGISTRY: dict[str, AuditRuleDefinition] = {
    "LH-ABU-001": AuditRuleDefinition(
        rule_id="LH-ABU-001",
        title="Missing Rate-Limiting on Authentication or Sensitive Endpoint",
        severity=FindingSeverity.CRITICAL,
        category="Rate Limiting",
        description=(
            "Sensitive routes (/login, /auth, /token, /password-reset, /otp, /register, "
            "/checkout) lack rate limiting, limit_req directives, or quotas."
        ),
        remediation=(
            "Configure explicit rate limits on sensitive endpoints using sliding-window or "
            "leaky-bucket algorithms at the API gateway."
        ),
    ),
    "LH-ABU-002": AuditRuleDefinition(
        rule_id="LH-ABU-002",
        title="Spoofable Rate-Limit Key (Unvalidated Header Trust)",
        severity=FindingSeverity.CRITICAL,
        category="Key Integrity",
        description=(
            "Rate limiter keys on X-Forwarded-For or client headers without validating trusted "
            "proxy CIDRs, enabling trivial header spoofing bypasses."
        ),
        remediation=(
            "Define explicit trusted reverse proxy CIDRs and use socket remote addresses or "
            "canonicalized client IPs for rate-limit keys."
        ),
    ),
    "LH-ABU-003": AuditRuleDefinition(
        rule_id="LH-ABU-003",
        title="Missing Account Lockout or Progressive Backoff",
        severity=FindingSeverity.HIGH,
        category="Lockout",
        description=(
            "Authentication endpoints lack account lockout thresholds after repeated failures or "
            "fail to enforce exponential backoff delays."
        ),
        remediation=(
            "Implement progressive exponential backoff and temporary account lockouts after 5 "
            "consecutive failed authentication attempts."
        ),
    ),
    "LH-ABU-004": AuditRuleDefinition(
        rule_id="LH-ABU-004",
        title="Permissive Rate-Limit Threshold Vulnerable to Brute-Force",
        severity=FindingSeverity.HIGH,
        category="Thresholds",
        description=(
            "Configured rate limits on sensitive endpoints exceed safe thresholds (> 30 "
            "requests/minute on auth/OTP routes or burst_size > 100)."
        ),
        remediation=(
            "Tighten rate-limiting quotas on sensitive routes to <= 10 requests per minute with "
            "strict burst enforcement."
        ),
    ),
    "LH-ABU-005": AuditRuleDefinition(
        rule_id="LH-ABU-005",
        title="Missing Connection Limit or Slowloris Timeout Defense",
        severity=FindingSeverity.HIGH,
        category="DoS Defense",
        description=(
            "Web servers or reverse proxies lack per-IP concurrent connection limits (limit_conn) "
            "or set client header/body timeouts above 60s."
        ),
        remediation=(
            "Configure per-IP concurrent connection limits (limit_conn) and reduce client "
            "header/body read timeouts to <= 30 seconds."
        ),
    ),
    "LH-ABU-006": AuditRuleDefinition(
        rule_id="LH-ABU-006",
        title="Distributed Brute-Force or Enumeration Velocity Anomaly",
        severity=FindingSeverity.HIGH,
        category="Velocity Anomaly",
        description=(
            "Runtime telemetry exhibits high-frequency 401/403/404/429 bursts, sequential "
            "identifier enumeration, or distributed credential stuffing."
        ),
        remediation=(
            "Deploy global IP reputation filtering, automated perimeter sinkholing, and "
            "behavioral anomaly throttling."
        ),
    ),
    "LH-ABU-007": AuditRuleDefinition(
        rule_id="LH-ABU-007",
        title="Missing Bot Challenge, Proof-of-Work, or CAPTCHA Step-Up",
        severity=FindingSeverity.MEDIUM,
        category="Bot Mitigation",
        description=(
            "Public signup, password reset, or high-volume scraping-prone endpoints omit bot "
            "challenges, proof-of-work, or adaptive verification."
        ),
        remediation=(
            "Integrate automated bot protection (Cloudflare Turnstile, reCAPTCHA, or "
            "proof-of-work) on public entry forms."
        ),
    ),
    "LH-ABU-008": AuditRuleDefinition(
        rule_id="LH-ABU-008",
        title="Fail-Open Rate-Limiter Store or Missing Window TTL",
        severity=FindingSeverity.HIGH,
        category="Resilience",
        description=(
            "Distributed rate limiter is configured with fail_open: true on store errors, "
            "fixed-window burst gaps, or keys missing atomic TTL."
        ),
        remediation=(
            "Configure fail-closed behavior for sensitive routes, migrate to sliding-window logs, "
            "and ensure atomic key expiration."
        ),
    ),
    "LH-ABU-009": AuditRuleDefinition(
        rule_id="LH-ABU-009",
        title="Missing Payload Cost / GraphQL Query Complexity Budget",
        severity=FindingSeverity.MEDIUM,
        category="Compute Budget",
        description=(
            "GraphQL, search, or bulk export endpoints lack query depth/complexity limits or "
            "compute budgets, risking resource exhaustion DoS."
        ),
        remediation=(
            "Enforce static GraphQL query complexity analysis, limit max query depth, and apply "
            "per-tenant compute quotas."
        ),
    ),
    "LH-ABU-010": AuditRuleDefinition(
        rule_id="LH-ABU-010",
        title="Missing Standard Rate-Limit Telemetry Headers or Retry-After",
        severity=FindingSeverity.LOW,
        category="Telemetry Quality",
        description=(
            "Rate-limiting responses omit standard RateLimit-* headers or Retry-After, or disable "
            "structured audit logging on 429 events."
        ),
        remediation=(
            "Include standard IETF RateLimit-* and Retry-After headers in 429 responses and enable "
            "detailed rate-limit audit logging."
        ),
    ),
}
