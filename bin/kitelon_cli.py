#!/usr/bin/env python3
"""Interactive REPL (`kitelon-cli`)."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from kitelon_engine.cli.shell import KitelonShell, VERSION
from kitelon_log import get_logger


def require_root() -> None:
    if os.geteuid() != 0:
        print("kitelon-cli must be run as root", file=sys.stderr)
        raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Kitelon interactive console")
    parser.add_argument(
        "-c",
        "--command",
        help='Run command(s) and exit (supports ; and && chaining)',
    )
    parser.add_argument(
        "--no-intro",
        action="store_true",
        help="Skip startup banner",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"kitelon-cli {VERSION}",
    )
    args = parser.parse_args()

    require_root()

    cli_logger = get_logger("cli")

    shell = KitelonShell(show_intro=not args.no_intro)

    if args.command:
        cli_logger.info("one-shot command=%r", args.command)
        shell.onecmd_plus_hooks(args.command)
        ok = shell.last_result is not False
        return 0 if ok else 1

    shell.cmdloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
