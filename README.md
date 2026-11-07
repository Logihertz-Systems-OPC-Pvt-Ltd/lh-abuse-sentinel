# lh-abuse-sentinel

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-abuse-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-abuse-sentinel/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise api rate limiting & anti-automation developed by **Logihertz Systems (OPC) Private Limited**.

Audits API gateway rate-limiting manifests, Nginx throttling zones, Redis sliding-window counters, and request velocity logs to detect missing brute-force defense, spoofable rate keys, and credential-stuffing abuse.

---

## Key Features

- **Multi-Source Gateway & Telemetry Ingestion**: Audits Kong, Envoy, Express, Nginx (`limit_req_zone`, `limit_req`), Redis token buckets, and live access log streams.
- **Brute-Force & Credential Stuffing Detection**: Audits authentication and sensitive routes (`/login`, `/auth`, `/password-reset`, `/otp`, `/checkout`) for missing or overly permissive quotas.
- **Spoofable Client IP Key Analysis**: Flags rate limiters keyed on `X-Forwarded-For` or `X-Real-IP` without trusted proxy CIDR validation, preventing trivial bypasses via header manipulation.
- **Slowloris & Connection Exhaustion Defense**: Detects missing concurrent connection caps (`limit_conn`) and excessive client header/body timeouts.
- **Fail-Open Store & Expiration Auditing**: Identifies distributed counter configurations that fail open during outages or omit atomic TTL expiration.
- **Multi-Format Reporting**: Outputs colored terminal tables via `rich`, structured JSON for SIEM pipelines, and OASIS SARIF v2.1.0 for CI/CD security tabs.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-ABU-001` | `CRITICAL` | Missing Rate-Limiting on Authentication or Sensitive Endpoint — high-risk routes (/login, /auth, /token, /otp) missing rate limiting |
| `LH-ABU-002` | `CRITICAL` | Spoofable Rate-Limit Key — client header trust (X-Forwarded-For) without trusted proxy CIDR validation |
| `LH-ABU-003` | `HIGH` | Missing Account Lockout or Progressive Exponential Backoff — auth policies lacking progressive backoff delays |
| `LH-ABU-004` | `HIGH` | Permissive Rate-Limit Threshold Vulnerable to Brute-Force — excessive request quotas (> 30 req/min on auth routes) |
| `LH-ABU-005` | `HIGH` | Missing Concurrent Connection Limit or Slowloris Timeout Defense — missing connection limits or body timeouts > 60s |
| `LH-ABU-006` | `HIGH` | Distributed Brute-Force or Enumeration Velocity Anomaly — high-frequency 401/403/404 response spikes in telemetry |
| `LH-ABU-007` | `MEDIUM` | Missing Bot Challenge, Proof-of-Work, or Turnstile Step-Up — public form or scraping-prone routes lacking CAPTCHA/bot checks |
| `LH-ABU-008` | `HIGH` | Fail-Open Rate-Limiter Store or Missing Sliding-Window TTL — Redis counter fail_open: true or missing atomic TTL |
| `LH-ABU-009` | `MEDIUM` | Missing Payload Cost / GraphQL Query Complexity Budget — search or GraphQL endpoints lacking query complexity budgets |
| `LH-ABU-010` | `LOW` | Missing Standard Rate-Limit Telemetry Headers or Retry-After — throttling policies omitting Retry-After or 429 headers |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-abuse-sentinel.git
cd lh-abuse-sentinel

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-abuse` (also accessible via `lh-abuse`, `lh-abuse-sentinel`).

```bash
# Scan an API gateway manifest or Nginx configuration
lh-abuse scan gateway.yaml

# Audit request velocity telemetry log
lh-abuse scan access.log --format json

# Export findings to OASIS SARIF for GitHub Code Scanning
lh-abuse scan ./config/ --format sarif --output abuse-findings.sarif

# Filter findings by minimum severity threshold
lh-abuse scan ./config/ --min-severity HIGH
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
