# ==============================================================================
# Product:       lh-abuse-sentinel (lh-abuse)
# Module:        src.lh_abuse_sentinel.throttle_parser
# Role:          Input Parser & Configuration Ingestion
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Parsers for rate-limiting configurations, Nginx configs, and request telemetry."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any

import yaml

from lh_abuse_sentinel.models import RateLimitPolicy, RequestVelocityEvent


def _extract_bool(data: dict[str, Any], aliases: list[str]) -> bool | None:
    """Extract boolean value checking case-insensitive alias keys."""
    normalized = {k.strip().lower().replace("_", " "): v for k, v in data.items()}
    for alias in aliases:
        norm_alias = alias.strip().lower().replace("_", " ")
        if norm_alias in normalized:
            val = normalized[norm_alias]
            if isinstance(val, bool):
                return val
            if isinstance(val, str):
                s = val.strip().lower()
                if s in ["true", "yes", "1", "on", "enabled", "strict"]:
                    return True
                if s in ["false", "no", "0", "off", "disabled"]:
                    return False
            if isinstance(val, int):
                return bool(val)
    return None


def _extract_str(data: dict[str, Any], aliases: list[str], default: str = "") -> str:
    """Extract string value checking case-insensitive alias keys."""
    normalized = {k.strip().lower().replace("_", " "): v for k, v in data.items()}
    for alias in aliases:
        norm_alias = alias.strip().lower().replace("_", " ")
        if norm_alias in normalized:
            val = normalized[norm_alias]
            if val is not None:
                return str(val).strip()
    return default


def _extract_int(data: dict[str, Any], aliases: list[str]) -> int | None:
    """Extract integer value checking case-insensitive alias keys."""
    normalized = {k.strip().lower().replace("_", " "): v for k, v in data.items()}
    for alias in aliases:
        norm_alias = alias.strip().lower().replace("_", " ")
        if norm_alias in normalized:
            val = normalized[norm_alias]
            try:
                return int(val)
            except (ValueError, TypeError):
                continue
    return None


def _extract_list(data: dict[str, Any], aliases: list[str]) -> list[str]:
    """Extract string list checking case-insensitive alias keys."""
    normalized = {k.strip().lower().replace("_", " "): v for k, v in data.items()}
    for alias in aliases:
        norm_alias = alias.strip().lower().replace("_", " ")
        if norm_alias in normalized:
            val = normalized[norm_alias]
            if isinstance(val, list):
                return [str(x).strip() for x in val if x is not None]
            if isinstance(val, str):
                return [x.strip() for x in val.split(",") if x.strip()]
    return []


def _dict_to_rate_limit_policy(
    data: dict[str, Any], source_file: str, line_no: int
) -> RateLimitPolicy:
    """Convert parsed dictionary into a RateLimitPolicy object."""
    policy_id = _extract_str(data, ["policy_id", "id", "name", "rule_id"], f"pol-{line_no}")
    name = _extract_str(data, ["name", "title", "description"], policy_id)
    route = _extract_str(data, ["target_route", "route", "path", "endpoint", "url"], "*")

    rl_enabled = _extract_bool(data, ["rate_limit_enabled", "enabled", "enable_rate_limit"])
    rpm = _extract_int(
        data, ["requests_per_minute", "rpm", "rate", "limit", "max_requests_per_minute"]
    )
    burst = _extract_int(data, ["burst_size", "burst", "max_burst"])
    key = _extract_str(data, ["key_by", "key", "limit_by", "rate_limit_key"]).lower()

    trusted_proxies = _extract_list(
        data, ["trusted_proxies", "trusted_proxy_cidrs", "set_real_ip_from"]
    )
    trust_any = _extract_bool(data, ["trust_any_proxy", "trust_all_proxies"])

    lockout_en = _extract_bool(data, ["lockout_enabled", "account_lockout", "lockout"])
    max_fails = _extract_int(data, ["max_failed_attempts", "max_attempts", "lockout_threshold"])
    backoff = _extract_bool(data, ["exponential_backoff", "progressive_backoff", "backoff"])

    max_conn = _extract_int(
        data, ["max_concurrent_connections", "limit_conn", "concurrent_connections"]
    )
    hdr_to = _extract_int(
        data, ["client_header_timeout_seconds", "client_header_timeout", "header_timeout"]
    )
    body_to = _extract_int(
        data, ["client_body_timeout_seconds", "client_body_timeout", "body_timeout"]
    )

    challenge_en = _extract_bool(
        data, ["challenge_enabled", "captcha_enabled", "turnstile_enabled", "proof_of_work"]
    )
    fail_open = _extract_bool(data, ["fail_open", "bypass_on_error", "fail_open_on_redis_error"])
    algorithm = _extract_str(data, ["algorithm", "strategy", "type"]).lower()
    ttl = _extract_int(data, ["ttl_seconds", "ttl", "window_ttl", "counter_ttl"])

    max_complexity = _extract_int(
        data, ["max_query_complexity", "graphql_max_complexity", "query_complexity"]
    )
    max_depth = _extract_int(data, ["max_query_depth", "graphql_max_depth", "query_depth"])

    send_hdrs = _extract_bool(data, ["send_headers", "rate_limit_headers", "standard_headers"])
    retry_after = _extract_bool(data, ["include_retry_after", "retry_after", "send_retry_after"])
    audit_log = _extract_bool(data, ["audit_logging", "log_rate_limit_events", "decision_logging"])

    return RateLimitPolicy(
        policy_id=policy_id,
        name=name,
        target_route=route,
        rate_limit_enabled=rl_enabled,
        requests_per_minute=rpm,
        burst_size=burst,
        key_by=key,
        trusted_proxies=trusted_proxies,
        trust_any_proxy=trust_any,
        lockout_enabled=lockout_en,
        max_failed_attempts=max_fails,
        exponential_backoff=backoff,
        max_concurrent_connections=max_conn,
        client_header_timeout_seconds=hdr_to,
        client_body_timeout_seconds=body_to,
        challenge_enabled=challenge_en,
        fail_open=fail_open,
        algorithm=algorithm,
        ttl_seconds=ttl,
        max_query_complexity=max_complexity,
        max_query_depth=max_depth,
        send_headers=send_hdrs,
        include_retry_after=retry_after,
        audit_logging=audit_log,
        source_file=source_file,
        line_number=line_no,
    )


def _dict_to_velocity_event(
    data: dict[str, Any], source_file: str, line_no: int
) -> RequestVelocityEvent:
    """Convert parsed dictionary into a RequestVelocityEvent object."""
    ev_id = _extract_str(data, ["event_id", "id", "log_id"], f"vel-{line_no}")
    ts = _extract_str(data, ["timestamp", "time", "date", "datetime"])
    ip = _extract_str(data, ["client_ip", "ip", "remote_addr", "source_ip"])
    route = _extract_str(data, ["route", "path", "endpoint", "url", "page"], "/")
    status = _extract_int(data, ["status_code", "status", "code"]) or 200
    user = _extract_str(data, ["user_identifier", "user", "username", "account_id"])

    return RequestVelocityEvent(
        event_id=ev_id,
        timestamp=ts,
        client_ip=ip,
        route=route,
        status_code=status,
        user_identifier=user,
        source_file=source_file,
        line_number=line_no,
    )


def parse_yaml_file(path: Path) -> tuple[list[RateLimitPolicy], list[RequestVelocityEvent]]:
    # --- Multi-Format Parsing & Normalization Engine ---
    # Autodetects manifest formats (JSON, YAML, .conf, .env, CSV, JSONL),
    # applies fallback decoders, recovers from malformed lines, and standardizes
    # raw configuration attributes into typed domain model instances.
    """Parse YAML rate-limiting policies and velocity events."""
    policies: list[RateLimitPolicy] = []
    events: list[RequestVelocityEvent] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        loaded = yaml.safe_load(content)

        if isinstance(loaded, list):
            for idx, item in enumerate(loaded, start=1):
                if isinstance(item, dict):
                    if "status_code" in item or "status" in item:
                        events.append(_dict_to_velocity_event(item, str(path), idx))
                    else:
                        policies.append(_dict_to_rate_limit_policy(item, str(path), idx))
        elif isinstance(loaded, dict):
            if "policies" in loaded and isinstance(loaded["policies"], list):
                for idx, item in enumerate(loaded["policies"], start=1):
                    if isinstance(item, dict):
                        policies.append(_dict_to_rate_limit_policy(item, str(path), idx))
            elif "events" in loaded and isinstance(loaded["events"], list):
                for idx, item in enumerate(loaded["events"], start=1):
                    if isinstance(item, dict):
                        events.append(_dict_to_velocity_event(item, str(path), idx))
            else:
                policies.append(_dict_to_rate_limit_policy(loaded, str(path), 1))
    except Exception:
        return policies, events
    return policies, events


def parse_json_file(path: Path) -> tuple[list[RateLimitPolicy], list[RequestVelocityEvent]]:
    """Parse JSON rate-limiting policies or telemetry event stream."""
    policies: list[RateLimitPolicy] = []
    events: list[RequestVelocityEvent] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace").strip()
        if not content:
            return [], []

        if content.startswith("["):
            loaded = json.loads(content)
            if isinstance(loaded, list):
                for idx, item in enumerate(loaded, start=1):
                    if isinstance(item, dict):
                        if "status_code" in item or "status" in item:
                            events.append(_dict_to_velocity_event(item, str(path), idx))
                        else:
                            policies.append(_dict_to_rate_limit_policy(item, str(path), idx))
                return policies, events
        elif content.startswith("{"):
            try:
                loaded = json.loads(content)
                if isinstance(loaded, dict):
                    if "policies" in loaded and isinstance(loaded["policies"], list):
                        for idx, item in enumerate(loaded["policies"], start=1):
                            if isinstance(item, dict):
                                policies.append(_dict_to_rate_limit_policy(item, str(path), idx))
                        return policies, events
                    elif "events" in loaded and isinstance(loaded["events"], list):
                        for idx, item in enumerate(loaded["events"], start=1):
                            if isinstance(item, dict):
                                events.append(_dict_to_velocity_event(item, str(path), idx))
                        return policies, events
                    elif "status_code" in loaded or "status" in loaded:
                        events.append(_dict_to_velocity_event(loaded, str(path), 1))
                        return policies, events
                    else:
                        policies.append(_dict_to_rate_limit_policy(loaded, str(path), 1))
                        return policies, events
            except json.JSONDecodeError:
                _ = None

        # NDJSON fallback
        for idx, line in enumerate(content.splitlines(), start=1):
            clean = line.strip()
            if clean:
                try:
                    obj = json.loads(clean)
                    if isinstance(obj, dict):
                        if "status_code" in obj or "status" in obj:
                            events.append(_dict_to_velocity_event(obj, str(path), idx))
                        else:
                            policies.append(_dict_to_rate_limit_policy(obj, str(path), idx))
                except json.JSONDecodeError:
                    continue
    except Exception:
        return policies, events
    return policies, events


def parse_conf_file(path: Path) -> tuple[list[RateLimitPolicy], list[RequestVelocityEvent]]:
    """Parse Nginx reverse proxy configuration for limit_req and limit_conn directives."""
    policies: list[RateLimitPolicy] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")

        # Global or http-level directives
        trusted_proxies = re.findall(r"set_real_ip_from\s+([^;]+);", content)
        rate_zones = re.findall(
            r"limit_req_zone\s+([^\s]+)\s+zone=([^:]+):[^\s]+\s+rate=([^\s;]+)", content
        )
        conn_zones = re.findall(r"limit_conn_zone\s+([^\s]+)\s+zone=([^:]+):", content)

        # Timeouts
        hdr_to_match = re.search(r"client_header_timeout\s+(\d+)s?;", content)
        hdr_timeout = int(hdr_to_match.group(1)) if hdr_to_match else None
        body_to_match = re.search(r"client_body_timeout\s+(\d+)s?;", content)
        body_timeout = int(body_to_match.group(1)) if body_to_match else None

        # Location blocks
        location_blocks = re.findall(r"location\s+([^{]+)\{([^}]+)\}", content, re.DOTALL)

        for idx, (route_raw, block_body) in enumerate(location_blocks, start=1):
            route = route_raw.strip()
            data: dict[str, Any] = {
                "route": route,
                "name": f"nginx-loc-{idx}",
                "trusted_proxies": [p.strip() for p in trusted_proxies],
                "client_header_timeout_seconds": hdr_timeout,
                "client_body_timeout_seconds": body_timeout,
            }

            # Check limit_req
            m_req = re.search(r"limit_req\s+zone=([^\s;]+)(?:\s+burst=(\d+))?", block_body)
            if m_req:
                data["rate_limit_enabled"] = True
                zone_name = m_req.group(1)
                burst = int(m_req.group(2)) if m_req.group(2) else 0
                data["burst_size"] = burst

                # Resolve zone rate
                for key_var, z_name, rate_str in rate_zones:
                    if z_name == zone_name:
                        data["key_by"] = key_var.replace("$", "").lower()
                        if "r/m" in rate_str:
                            data["requests_per_minute"] = int(rate_str.replace("r/m", ""))
                        elif "r/s" in rate_str:
                            data["requests_per_minute"] = int(rate_str.replace("r/s", "")) * 60
            else:
                data["rate_limit_enabled"] = False

            # Check limit_conn
            m_conn = re.search(r"limit_conn\s+([^\s]+)\s+(\d+);", block_body)
            if m_conn:
                data["max_concurrent_connections"] = int(m_conn.group(2))
            elif conn_zones:
                data["max_concurrent_connections"] = 10

            policies.append(_dict_to_rate_limit_policy(data, str(path), idx))

        if not policies:
            # Server level fallback
            data = {
                "route": "*",
                "name": "nginx-server-root",
                "trusted_proxies": [p.strip() for p in trusted_proxies],
                "client_header_timeout_seconds": hdr_timeout,
                "client_body_timeout_seconds": body_timeout,
                "rate_limit_enabled": len(rate_zones) > 0,
            }
            policies.append(_dict_to_rate_limit_policy(data, str(path), 1))
    except Exception:
        return policies, []
    return policies, []


def parse_csv_file(path: Path) -> tuple[list[RateLimitPolicy], list[RequestVelocityEvent]]:
    """Parse CSV request velocity telemetry logs."""
    events: list[RequestVelocityEvent] = []
    try:
        with path.open(mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader, start=2):
                if not row:
                    continue
                events.append(_dict_to_velocity_event(dict(row), str(path), idx))
    except Exception:
        return [], events
    return [], events


def parse_throttle_file(path: Path) -> tuple[list[RateLimitPolicy], list[RequestVelocityEvent]]:
    """Dispatch file parsing based on extension and contents."""
    suffix = path.suffix.lower()
    if suffix in [".yaml", ".yml"]:
        return parse_yaml_file(path)
    if suffix in [".json", ".jsonl"]:
        return parse_json_file(path)
    if suffix in [".conf", ".nginx"]:
        return parse_conf_file(path)
    if suffix == ".csv":
        return parse_csv_file(path)

    # Fallbacks
    p, e = parse_yaml_file(path)
    if p or e:
        return p, e
    p_j, e_j = parse_json_file(path)
    if p_j or e_j:
        return p_j, e_j
    return parse_conf_file(path)


def find_throttle_files(root: Path) -> list[Path]:
    """Find all supported rate-limit configuration and telemetry files under root path."""
    if not root.exists():
        return []

    if root.is_file():
        return [root]

    supported_suffixes = {".yaml", ".yml", ".json", ".jsonl", ".conf", ".nginx", ".csv"}
    files: list[Path] = []
    for item in root.rglob("*"):
        if item.is_file() and item.suffix.lower() in supported_suffixes:
            files.append(item)
    return sorted(files)
