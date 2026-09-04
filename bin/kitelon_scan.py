#!/usr/bin/env python3
"""Kitelon scan CLI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_BIN_DIR = Path(__file__).resolve().parent
if str(_BIN_DIR) not in sys.path:
    sys.path.insert(0, str(_BIN_DIR))

from kitelon_engine.pipeline import run_scan  # noqa: E402
from kitelon_scan_config import VALID_MODE_IDS  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Kitelon scan engine")
    parser.add_argument("--target", "-t", required=True, help="Target host, domain, or CIDR")
    parser.add_argument("--mode", "-m", default="normal", choices=sorted(VALID_MODE_IDS))
    parser.add_argument("--workspace", "-w", required=True, help="Workspace alias")
    parser.add_argument("--resume", "-rr", action="store_true", help="Skip completed steps")
    parser.add_argument("--osint", "-o", action="store_true", help="Enable OSINT modules")
    parser.add_argument("--recon", "-re", action="store_true", help="Enable recon modules")
    parser.add_argument("--full-port", "-fp", action="store_true", help="Full port scan")
    parser.add_argument("--port", "-p", type=int, help="Single port")
    parser.add_argument("--testssl", "-ts", action="store_true", help="Enable testssl")
    parser.add_argument("--ffuf", "-fu", action="store_true", help="Enable ffuf dir brute")
    parser.add_argument("--preset", "-pr", help="Load conf/presets/<name>.conf overrides")
    parser.add_argument("--target-file", "-f", help="File of targets for mass modes")
    parser.add_argument("--job-id", type=int, default=None, help="Optional queue job id")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    options = {
        "resume": args.resume,
        "osint": args.osint,
        "recon": args.recon,
        "fullportscan": args.full_port,
        "port": args.port,
        "enable_testssl": args.testssl or None,
        "enable_ffuf": args.ffuf or None,
        "preset": args.preset,
        "target_file": args.target_file,
    }
    options = {k: v for k, v in options.items() if v is not None}
    return run_scan(
        target=args.target,
        mode=args.mode,
        workspace=args.workspace,
        options=options,
        job_id=args.job_id,
    )


if __name__ == "__main__":
    raise SystemExit(main())
