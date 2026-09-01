"""ffuf directory brute-force wrapper."""


import json
from pathlib import Path
from typing import Any

from kitelon_engine.context import ScanContext
from kitelon_engine.tools.base import run_cmd, which


def run_ffuf(ctx: ScanContext, url: str, wordlist: Path, output: Path) -> bool:
    ffuf_bin = which("ffuf")
    if not ffuf_bin or not wordlist.is_file():
        ctx.log("ffuf or wordlist unavailable, skip ffuf")
        return False

    args = [
        ffuf_bin,
        "-u",
        f"{url.rstrip('/')}/FUZZ",
        "-w",
        str(wordlist),
        "-json",
        "-o",
        str(output),
        "-t",
        str(min(ctx.threads, 40)),
        "-mc",
        "200,204,301,302,307,401,403",
        "-noninteractive",
    ]
    if url.startswith("https"):
        args.append("-k")
    ctx.log(f"running ffuf on {url}")
    run_cmd(args, timeout=3600)
    output.parent.mkdir(parents=True, exist_ok=True)
    return output.is_file()


def parse_ffuf_json(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    hits: list[dict[str, Any]] = []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            hits = data
        elif isinstance(data, dict):
            if "results" in data:
                hits = data.get("results", [])
            elif data.get("url"):
                hits = [data]
            else:
                hits = []
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                hits.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    rows: list[dict[str, Any]] = []
    for item in hits:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or item.get("input", {}).get("FUZZ", ""))
        status = item.get("status") or item.get("statuscode")
        rows.append({"url": url, "status": status, "length": item.get("length")})
    return rows
