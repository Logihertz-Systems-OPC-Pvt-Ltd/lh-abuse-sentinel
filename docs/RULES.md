# Security Rules Reference: lh-abuse-sentinel

An enterprise api rate-limiting & velocity abuse sentinel developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-abuse-sentinel`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-ABU-001` | `CRITICAL` | Rate Limiting | Missing Rate-Limiting on Authentication or Sensitive Endpoint |
| `LH-ABU-002` | `CRITICAL` | Key Validation | Spoofable Rate-Limit Key (Unvalidated Header Trust) |
| `LH-ABU-003` | `HIGH` | Lockout Policy | Missing Account Lockout or Progressive Exponential Backoff |
| `LH-ABU-004` | `HIGH` | Thresholds | Permissive Rate-Limit Threshold Vulnerable to Brute-Force |
| `LH-ABU-005` | `HIGH` | Connection Control | Missing Concurrent Connection Limit or Slowloris Timeout Defense |
| `LH-ABU-006` | `HIGH` | Anomaly Detection | Distributed Brute-Force or Enumeration Velocity Anomaly in Telemetry |
| `LH-ABU-007` | `MEDIUM` | Bot Mitigation | Missing Bot Challenge, Proof-of-Work, or Turnstile Step-Up |
| `LH-ABU-008` | `HIGH` | Storage Hygiene | Fail-Open Rate-Limiter Store or Missing Sliding-Window TTL |
| `LH-ABU-009` | `MEDIUM` | Cost Throttling | Missing Payload Cost / GraphQL Query Complexity Budget |
| `LH-ABU-010` | `LOW` | Telemetry | Missing Standard Rate-Limit Telemetry Headers or Retry-After |

---

## Granular Rule Specifications

### `LH-ABU-001`: Missing Rate-Limiting on Authentication or Sensitive Endpoint

- **Severity**: `CRITICAL`
- **Category**: `Rate Limiting`
- **Description**: Sensitive routes (/login, /auth, /token, /password-reset, /otp, /register, /checkout) lack rate limiting or quotas.
- **Remediation**: Configure explicit rate limits on sensitive endpoints using sliding-window or leaky-bucket algorithms at the API gateway.

---

### `LH-ABU-002`: Spoofable Rate-Limit Key (Unvalidated Header Trust)

- **Severity**: `CRITICAL`
- **Category**: `Key Validation`
- **Description**: Rate limiters keyed on X-Forwarded-For or X-Real-IP without trusted proxy CIDR validation, allowing trivial bypass via header rotation.
- **Remediation**: Validate client IP against trusted reverse-proxy CIDR ranges or key rate limits on authenticated user tokens.

---

### `LH-ABU-003`: Missing Account Lockout or Progressive Exponential Backoff

- **Severity**: `HIGH`
- **Category**: `Lockout Policy`
- **Description**: Authentication policies lacking failed-attempt lockout thresholds or progressive backoff delays.
- **Remediation**: Enforce temporary account lockouts after 5 failed attempts with exponential progressive backoff delays.

---

### `LH-ABU-004`: Permissive Rate-Limit Threshold Vulnerable to Brute-Force

- **Severity**: `HIGH`
- **Category**: `Thresholds`
- **Description**: Overly generous rate limits on sensitive endpoints (> 30 requests/minute on auth routes) permitting credential stuffing.
- **Remediation**: Reduce authentication rate limits to <= 5-10 requests/minute per IP/account with burst caps.

---

### `LH-ABU-005`: Missing Concurrent Connection Limit or Slowloris Timeout Defense

- **Severity**: `HIGH`
- **Category**: `Connection Control`
- **Description**: Web servers or gateways missing per-IP connection limits or configured with client body/header timeouts > 60s.
- **Remediation**: Configure limit_conn in Nginx or gateway concurrent connection caps with strict 10s header/body timeouts.

---

### `LH-ABU-006`: Distributed Brute-Force or Enumeration Velocity Anomaly in Telemetry

- **Severity**: `HIGH`
- **Category**: `Anomaly Detection`
- **Description**: High-frequency 401/403/404 response spikes or distributed credential-stuffing patterns observed across client records.
- **Remediation**: Deploy edge IP reputation filtering, rate-limit clustering, and automated temporary ASN/IP banning.

---

### `LH-ABU-007`: Missing Bot Challenge, Proof-of-Work, or Turnstile Step-Up

- **Severity**: `MEDIUM`
- **Category**: `Bot Mitigation`
- **Description**: Public form, signup, or password-reset endpoints lacking adaptive bot challenge-response mechanisms.
- **Remediation**: Implement Cloudflare Turnstile, proof-of-work puzzles, or CAPTCHA step-ups on unauthenticated public forms.

---

### `LH-ABU-008`: Fail-Open Rate-Limiter Store or Missing Sliding-Window TTL

- **Severity**: `HIGH`
- **Category**: `Storage Hygiene`
- **Description**: Distributed rate limiters configured with fail_open: true on backend error or counter keys missing atomic TTL expiration.
- **Remediation**: Set rate-limiting stores to fail-closed on critical routes and enforce strict atomic TTL on all counter keys.

---

### `LH-ABU-009`: Missing Payload Cost / GraphQL Query Complexity Budget

- **Severity**: `MEDIUM`
- **Category**: `Cost Throttling`
- **Description**: Bulk export, search, or GraphQL endpoints lacking query complexity budgets or per-tenant compute throttling.
- **Remediation**: Enforce query depth limits, max pagination page sizes (e.g., <= 100), and cost-weighted query throttling.

---

### `LH-ABU-010`: Missing Standard Rate-Limit Telemetry Headers or Retry-After

- **Severity**: `LOW`
- **Category**: `Telemetry`
- **Description**: Throttling policies that omit Retry-After, RateLimit-Limit, or RateLimit-Remaining headers.
- **Remediation**: Include standard IETF RFC draft RateLimit-* headers and Retry-After on all 429 response payloads.

---
