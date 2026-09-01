#!/usr/bin/env python3
"""Scan modes and job option flags for API, worker, and Web UI."""

import re
from typing import Any

# Canonical mode IDs (operator-facing). Batch modes expect -f / --target-file.
SCAN_MODES: list[dict[str, str]] = [
    {"id": "normal", "label": "Normal", "description": "Standard recon and vulnerability scan"},
    {"id": "stealth", "label": "Stealth", "description": "Quieter, slower enumeration"},
    {"id": "web", "label": "Web", "description": "HTTP/HTTPS ports 80 and 443"},
    {"id": "web-deep", "label": "Web deep", "description": "Deep web application scan (optional ZAP)"},
    {"id": "web-http", "label": "Web HTTP", "description": "Web stack on one HTTP port (use port option)"},
    {"id": "web-https", "label": "Web HTTPS", "description": "Web stack on one HTTPS port (use port option)"},
    {"id": "discover", "label": "Discover", "description": "Network discovery (CIDR)"},
    {"id": "recon", "label": "Recon", "description": "Subdomain enum and light port scan"},
    {"id": "osint", "label": "OSINT", "description": "Open-source intelligence"},
    {"id": "allports", "label": "All ports", "description": "Full TCP port scan, then web on 80/443"},
    {"id": "ports-only", "label": "Ports only", "description": "Full port scan without follow-on modules"},
    {"id": "ports-quick", "label": "Ports quick", "description": "Light port scan only"},
    {"id": "port", "label": "Port", "description": "Scan a single port (set port option)"},
    {"id": "vuln", "label": "Vuln", "description": "Vulnerability templates on web ports"},
    {"id": "batch-ports", "label": "Batch ports", "description": "All-port scan from target file"},
    {"id": "batch-web", "label": "Batch web", "description": "Web scan from target file"},
    {"id": "batch-webdeep", "label": "Batch web deep", "description": "Deep web scan from target file"},
    {"id": "batch-vuln", "label": "Batch vuln", "description": "Vuln scan from target file"},
    {"id": "batch-ports-fast", "label": "Batch ports (fast)", "description": "Fast multi-target port scan from file"},
    {"id": "full-audit", "label": "Full audit", "description": "OSINT, recon, web deep, and vuln modules"},
]

VALID_MODE_IDS = frozenset(m["id"] for m in SCAN_MODES)

SCAN_OPTIONS: list[dict[str, Any]] = [
    {"id": "resume", "label": "Resume", "description": "Skip steps that already have loot", "type": "bool", "flag": "-rr"},
    {"id": "osint", "label": "OSINT", "description": "Enable OSINT modules (-o)", "type": "bool", "flag": "-o"},
    {"id": "recon", "label": "Recon", "description": "Enable recon modules (-re)", "type": "bool", "flag": "-re"},
    {"id": "fullportscan", "label": "Full port scan", "description": "Scan all ports (-fp)", "type": "bool", "flag": "-fp"},
    {"id": "testssl", "label": "SSL/TLS scan", "description": "Run testssl.sh on HTTPS targets", "type": "bool", "flag": "--testssl"},
    {"id": "ffuf", "label": "ffuf dir brute", "description": "Run ffuf path discovery alongside dirsearch", "type": "bool", "flag": "--ffuf"},
    {"id": "preset", "label": "Preset", "description": "Load scan preset from conf/presets/", "type": "string", "flag": "--preset"},
    {"id": "port", "label": "Port", "description": "Limit to a specific port", "type": "number", "flag": "-p"},
]

_ALLOWED_FLAGS = {spec["flag"] for spec in SCAN_OPTIONS}
_FLAG_VALUE = {spec["flag"]: spec["type"] != "bool" for spec in SCAN_OPTIONS}
_PRESET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_FORBIDDEN_FLAGS = frozenset(
    {
        "--target",
        "-t",
        "--mode",
        "-m",
        "--workspace",
        "-w",
        "--job-id",
        "--target-file",
        "-f",
    }
)


def options_to_extra_args(options: dict[str, Any] | None) -> list[str]:
    if not options:
        return []
    extra: list[str] = []
    for spec in SCAN_OPTIONS:
        opt_id = spec["id"]
        if opt_id not in options or options[opt_id] in (None, "", False):
            continue
        value = options[opt_id]
        if spec["type"] == "bool":
            if value:
                extra.append(spec["flag"])
        elif spec["type"] == "number" and value not in (None, ""):
            port = _valid_port(value)
            if port is None:
                continue
            extra.extend([spec["flag"], port])
        elif spec["type"] == "string" and value not in (None, ""):
            preset = _valid_preset(value)
            if preset is None:
                continue
            extra.extend([spec["flag"], preset])
    return extra


def _valid_port(value: Any) -> str | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if 1 <= port <= 65535:
        return str(port)
    return None


def _valid_preset(value: Any) -> str | None:
    preset = str(value).strip()
    if not _PRESET_NAME.fullmatch(preset):
        return None
    return preset


def sanitize_extra_args(tokens: list[str] | str | None) -> list[str]:
    """Keep only scan-option flags the worker is allowed to pass through."""
    if not tokens:
        return []
    if isinstance(tokens, str):
        tokens = tokens.split()
    out: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in _FORBIDDEN_FLAGS or tok not in _ALLOWED_FLAGS:
            i += 1
            continue
        if _FLAG_VALUE.get(tok):
            if i + 1 >= len(tokens):
                i += 1
                continue
            val = tokens[i + 1]
            if tok == "--preset":
                preset = _valid_preset(val)
                if preset is None:
                    i += 2
                    continue
                val = preset
            if tok == "-p":
                port = _valid_port(val)
                if port is None:
                    i += 2
                    continue
                val = port
            out.extend([tok, val])
            i += 2
            continue
        out.append(tok)
        i += 1
    return out


def merge_job_scan_args(
    args: dict[str, Any] | None,
    *,
    trust_extra: bool = False,
) -> dict[str, Any]:
    """Normalize job args for storage (API) or execution (worker).

    When ``trust_extra`` is False (default), client ``extra_args`` are ignored
    unless an ``options`` dict is present: flags are rebuilt from options only.
    When ``trust_extra`` is True (worker re-read of stored jobs), existing
    ``extra_args`` are kept after allowlist sanitization.
    """
    merged = dict(args or {})
    stored_extra = merged.pop("extra_args", None)
    options = merged.pop("options", None)
    if options is not None:
        if not isinstance(options, dict):
            options = {}
        merged["extra_args"] = sanitize_extra_args(options_to_extra_args(options))
    elif trust_extra:
        merged["extra_args"] = sanitize_extra_args(stored_extra)
    else:
        merged["extra_args"] = []
    return merged


def scan_config_payload() -> dict[str, Any]:
    return {"modes": SCAN_MODES, "options": SCAN_OPTIONS}
