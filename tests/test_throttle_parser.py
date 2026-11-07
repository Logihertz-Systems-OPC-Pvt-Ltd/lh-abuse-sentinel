# ==============================================================================
# Product:       lh-abuse-sentinel (lh-abuse)
# Module:        tests.test_throttle_parser
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Tests for throttle_parser module."""

from __future__ import annotations

from pathlib import Path

from lh_abuse_sentinel.throttle_parser import (
    find_throttle_files,
    parse_conf_file,
    parse_csv_file,
    parse_json_file,
    parse_throttle_file,
    parse_yaml_file,
)


def test_parse_yaml_clean(sample_clean_yaml: Path) -> None:
    """Test parsing compliant YAML rate-limiting policy."""
    policies, events = parse_yaml_file(sample_clean_yaml)
    assert len(policies) == 1
    assert len(events) == 0
    p = policies[0]
    assert p.target_route == "/auth/login"
    assert p.rate_limit_enabled is True
    assert p.requests_per_minute == 10
    assert p.burst_size == 15
    assert p.key_by == "client_ip"
    assert "10.0.0.0/8" in p.trusted_proxies
    assert p.lockout_enabled is True
    assert p.max_failed_attempts == 5
    assert p.exponential_backoff is True
    assert p.max_concurrent_connections == 20
    assert p.client_header_timeout_seconds == 15
    assert p.challenge_enabled is True
    assert p.algorithm == "sliding_window"
    assert p.ttl_seconds == 60


def test_parse_yaml_malicious(sample_malicious_yaml: Path) -> None:
    """Test parsing insecure YAML policies."""
    policies, events = parse_yaml_file(sample_malicious_yaml)
    assert len(policies) == 9
    assert len(events) == 0


def test_parse_json_telemetry(sample_velocity_json: Path) -> None:
    """Test parsing JSON telemetry records."""
    policies, events = parse_json_file(sample_velocity_json)
    assert len(policies) == 0
    assert len(events) == 16  # 6 burst + 6 dist + 4 enum
    assert events[0].client_ip == "198.51.100.42"
    assert events[0].status_code == 401


def test_parse_ndjson(tmp_path: Path) -> None:
    """Test parsing newline-delimited JSON (NDJSON)."""
    ndjson_file = tmp_path / "traffic.jsonl"
    lines = [
        '{"event_id": "nd-1", "timestamp": "2026-11-01T10:00:00Z", "client_ip": "10.0.0.1", '
        '"route": "/api/v1/resource", "status_code": 200}',
        '{"event_id": "nd-2", "timestamp": "2026-11-01T10:00:01Z", "client_ip": "10.0.0.2", '
        '"route": "/api/v1/auth", "status_code": 401}',
    ]
    ndjson_file.write_text("\n".join(lines), encoding="utf-8")
    policies, events = parse_json_file(ndjson_file)
    assert len(policies) == 0
    assert len(events) == 2
    assert events[1].status_code == 401


def test_parse_nginx_conf(sample_nginx_conf: Path) -> None:
    """Test parsing Nginx configuration file."""
    policies, events = parse_conf_file(sample_nginx_conf)
    assert len(policies) >= 1
    assert len(events) == 0
    p = policies[0]
    assert p.requests_per_minute == 60  # 1r/s * 60 = 60 RPM
    assert p.burst_size == 5
    assert p.max_concurrent_connections == 10
    assert p.client_header_timeout_seconds == 15
    assert p.client_body_timeout_seconds == 20
    assert "10.0.0.0/8" in p.trusted_proxies


def test_parse_csv(sample_telemetry_csv: Path) -> None:
    """Test parsing CSV telemetry records."""
    policies, events = parse_csv_file(sample_telemetry_csv)
    assert len(policies) == 0
    assert len(events) == 5
    assert events[0].client_ip == "198.51.100.99"
    assert events[0].status_code == 401


def test_find_throttle_files_directory(tmp_path: Path) -> None:
    """Test finding supported throttle and telemetry files in directory."""
    (tmp_path / "policy.yaml").write_text("policy_id: p1", encoding="utf-8")
    (tmp_path / "events.json").write_text("[]", encoding="utf-8")
    (tmp_path / "server.conf").write_text("server {}", encoding="utf-8")
    (tmp_path / "telemetry.csv").write_text("timestamp,client_ip", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("ignored", encoding="utf-8")

    files = find_throttle_files(tmp_path)
    file_names = [f.name for f in files]
    assert "policy.yaml" in file_names
    assert "events.json" in file_names
    assert "server.conf" in file_names
    assert "telemetry.csv" in file_names
    assert "notes.txt" not in file_names


def test_find_throttle_files_single_file(tmp_path: Path) -> None:
    """Test find_throttle_files with a single file target."""
    f = tmp_path / "single.yml"
    f.write_text("policy_id: p1", encoding="utf-8")
    assert find_throttle_files(f) == [f]


def test_parse_throttle_file_dispatcher(sample_clean_yaml: Path) -> None:
    """Test parse_throttle_file dispatcher function."""
    policies, events = parse_throttle_file(sample_clean_yaml)
    assert len(policies) == 1
    assert len(events) == 0


def test_parse_malformed_json(tmp_path: Path) -> None:
    """Test parsing malformed JSON returns empty lists without unhandled exception."""
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{ incomplete json content ...", encoding="utf-8")
    policies, events = parse_json_file(bad_json)
    assert policies == []
    assert events == []


def test_parse_single_json_objects(tmp_path: Path) -> None:
    """Test parsing single policy dict and single event dict in JSON."""
    pol_file = tmp_path / "single_pol.json"
    pol_file.write_text('{"name": "P1", "route": "/login", "enabled": "on"}', encoding="utf-8")
    policies, events = parse_json_file(pol_file)
    assert len(policies) == 1
    assert policies[0].rate_limit_enabled is True

    evt_file = tmp_path / "single_evt.json"
    evt_file.write_text(
        '{"client_ip": "10.0.0.1", "route": "/login", "status": 401}', encoding="utf-8"
    )
    policies, events = parse_json_file(evt_file)
    assert len(events) == 1
    assert events[0].status_code == 401


def test_parse_variants_and_fallbacks(tmp_path: Path) -> None:
    """Test alias parsing, string booleans, and comma-separated lists."""
    yaml_file = tmp_path / "variants.yaml"
    content = (
        "name: Complex Policy\n"
        "route: /api\n"
        "enabled: strict\n"
        "lockout: off\n"
        "trusted_proxies: 10.0.0.1, 10.0.0.2\n"
        "burst: invalid_int\n"
    )
    yaml_file.write_text(content, encoding="utf-8")
    policies, _ = parse_yaml_file(yaml_file)
    assert len(policies) == 1
    p = policies[0]
    assert p.rate_limit_enabled is True
    assert p.lockout_enabled is False
    assert p.trusted_proxies == ["10.0.0.1", "10.0.0.2"]
    assert p.burst_size is None
