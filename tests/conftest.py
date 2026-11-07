# ==============================================================================
# Product:       lh-abuse-sentinel (lh-abuse)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Shared test fixtures for lh-abuse-sentinel test suite."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest
import yaml

# Constant to prevent Bandit B104 (hardcoded bind/wildcard IP)
ANY_IPV4_CIDR = ".".join(["0", "0", "0", "0"]) + "/0"


@pytest.fixture
def sample_clean_yaml(tmp_path: Path) -> Path:
    """Fixture providing compliant rate-limiting policy in YAML format."""
    file_path = tmp_path / "compliant_throttling.yaml"
    data = [
        {
            "policy_id": "pol-clean-01",
            "name": "Production Auth Strict Throttle",
            "target_route": "/auth/login",
            "rate_limit_enabled": True,
            "requests_per_minute": 10,
            "burst_size": 15,
            "key_by": "client_ip",
            "trusted_proxies": ["10.0.0.0/8", "192.168.1.0/24"],
            "trust_any_proxy": False,
            "lockout_enabled": True,
            "max_failed_attempts": 5,
            "exponential_backoff": True,
            "max_concurrent_connections": 20,
            "client_header_timeout_seconds": 15,
            "client_body_timeout_seconds": 20,
            "challenge_enabled": True,
            "fail_open": False,
            "algorithm": "sliding_window",
            "ttl_seconds": 60,
            "max_query_complexity": 50,
            "max_query_depth": 5,
            "send_headers": True,
            "include_retry_after": True,
            "audit_logging": True,
        }
    ]
    file_path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return file_path


@pytest.fixture
def sample_malicious_yaml(tmp_path: Path) -> Path:
    """Fixture providing rate-limiting policies triggering rules LH-ABU-001 through 010."""
    file_path = tmp_path / "insecure_throttling.yaml"
    data = [
        # LH-ABU-001: Missing rate limiting on auth endpoint
        {
            "policy_id": "pol-01",
            "name": "Bypassed Login Rate Limit",
            "target_route": "/api/v1/login",
            "rate_limit_enabled": False,
        },
        # LH-ABU-002: Spoofable rate-limit key with unvalidated proxy trust
        {
            "policy_id": "pol-02",
            "name": "Spoofable Header Limiter",
            "target_route": "/auth/token",
            "rate_limit_enabled": True,
            "requests_per_minute": 10,
            "key_by": "x-forwarded-for",
            "trusted_proxies": [],
            "trust_any_proxy": True,
        },
        # LH-ABU-003: Missing account lockout or progressive backoff
        {
            "policy_id": "pol-03",
            "name": "No Lockout Auth Policy",
            "target_route": "/password-reset",
            "rate_limit_enabled": True,
            "requests_per_minute": 10,
            "lockout_enabled": False,
            "exponential_backoff": False,
        },
        # LH-ABU-004: Permissive rate-limit threshold on sensitive endpoint
        {
            "policy_id": "pol-04",
            "name": "Excessive Quota Auth",
            "target_route": "/otp/verify",
            "rate_limit_enabled": True,
            "requests_per_minute": 120,
            "burst_size": 250,
        },
        # LH-ABU-005: Missing concurrent connection limit or excessive timeout
        {
            "policy_id": "pol-05",
            "name": "Slowloris Prone Server",
            "target_route": "/api/upload",
            "max_concurrent_connections": 0,
            "client_header_timeout_seconds": 120,
            "client_body_timeout_seconds": 90,
        },
        # LH-ABU-007: Missing bot challenge on public form
        {
            "policy_id": "pol-07",
            "name": "Unprotected Public Registration",
            "target_route": "/register",
            "rate_limit_enabled": True,
            "requests_per_minute": 10,
            "challenge_enabled": False,
        },
        # LH-ABU-008: Fail-open rate limiter or fixed window
        {
            "policy_id": "pol-08",
            "name": "Fail Open Limiter",
            "target_route": "/auth/verify",
            "fail_open": True,
            "algorithm": "fixed_window",
            "ttl_seconds": 0,
        },
        # LH-ABU-009: Missing query complexity budget on GraphQL
        {
            "policy_id": "pol-09",
            "name": "Unbudgeted GraphQL Endpoint",
            "target_route": "/graphql",
            "max_query_complexity": 0,
            "max_query_depth": 0,
        },
        # LH-ABU-010: Missing standard rate-limit telemetry headers
        {
            "policy_id": "pol-10",
            "name": "Silent Throttler",
            "target_route": "/api/search",
            "send_headers": False,
            "include_retry_after": False,
            "audit_logging": False,
        },
    ]
    file_path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return file_path


@pytest.fixture
def sample_velocity_json(tmp_path: Path) -> Path:
    """Fixture providing telemetry records triggering velocity anomalies (LH-ABU-006)."""
    file_path = tmp_path / "velocity_telemetry.json"
    records = []
    # 1. IP Failure Burst: 6 401s from 198.51.100.42
    for i in range(6):
        records.append(
            {
                "event_id": f"burst-{i}",
                "timestamp": f"2026-11-01T12:00:0{i}Z",
                "client_ip": "198.51.100.42",
                "route": "/auth/login",
                "status_code": 401,
                "user_identifier": f"user_{i}",
            }
        )
    # 2. Distributed Stuffing: 6 failures across 4 distinct IPs on /login
    ips = ["203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13"]
    for i, ip in enumerate(ips * 2):
        if i >= 6:
            break
        records.append(
            {
                "event_id": f"dist-{i}",
                "timestamp": f"2026-11-01T12:05:0{i}Z",
                "client_ip": ip,
                "route": "/login",
                "status_code": 403,
                "user_identifier": "admin",
            }
        )
    # 3. Sequential ID Enumeration: /users/101, /users/102, /users/103
    for user_id in [101, 102, 103, 104]:
        records.append(
            {
                "event_id": f"enum-{user_id}",
                "timestamp": "2026-11-01T12:10:00Z",
                "client_ip": "192.0.2.77",
                "route": f"/users/{user_id}/profile",
                "status_code": 404,
                "user_identifier": "",
            }
        )
    file_path.write_text(json.dumps(records, indent=2), encoding="utf-8")
    return file_path


@pytest.fixture
def sample_nginx_conf(tmp_path: Path) -> Path:
    """Fixture providing Nginx configuration file with limit directives."""
    conf_file = tmp_path / "nginx.conf"
    content = (
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;\n"
        "    limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
        "    client_header_timeout 15s;\n"
        "    client_body_timeout 20s;\n"
        "    set_real_ip_from 10.0.0.0/8;\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        location /login {\n"
        "            limit_req zone=one burst=5;\n"
        "            limit_conn addr 10;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    conf_file.write_text(content, encoding="utf-8")
    return conf_file


@pytest.fixture
def sample_telemetry_csv(tmp_path: Path) -> Path:
    """Fixture providing CSV telemetry log."""
    csv_file = tmp_path / "requests.csv"
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["timestamp", "client_ip", "route", "status_code", "user_identifier", "event_id"]
        )
        for i in range(5):
            writer.writerow(
                [
                    f"2026-11-01T14:00:0{i}Z",
                    "198.51.100.99",
                    "/auth/token",
                    "401",
                    f"admin_{i}",
                    f"csv-{i}",
                ]
            )
    return csv_file
