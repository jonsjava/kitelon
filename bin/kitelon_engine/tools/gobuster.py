from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.tools.base import run_cmd, which


def run_gobuster(ctx: ScanContext, url: str, wordlist: Path, output: Path) -> bool:
    gobuster = which("gobuster")
    if not gobuster or not wordlist.is_file():
        ctx.log("gobuster or wordlist unavailable, skip dir brute")
        return False

    args = [
        gobuster,
        "dir",
        "-u",
        url,
        "-w",
        str(wordlist),
        "-o",
        str(output),
        "-q",
        "-e",
    ]
    if url.startswith("https"):
        args.extend(["-k", "-r"])
    ctx.log(f"running gobuster on {url}")
    run_cmd(args, timeout=3600)
    output.parent.mkdir(parents=True, exist_ok=True)
    return output.is_file()


def run_dirsearch(ctx: ScanContext, url: str, wordlist: Path, output: Path) -> bool:
    dirsearch = which("dirsearch")
    if not dirsearch or not wordlist.is_file():
        return run_gobuster(ctx, url, wordlist, output)

    args = [
        dirsearch,
        "-u",
        url,
        "-w",
        str(wordlist),
        "-o",
        str(output),
        "--random-agent",
        "-t",
        str(min(ctx.threads, 30)),
    ]
    ctx.log(f"running dirsearch on {url}")
    run_cmd(args, timeout=3600)
    return output.is_file()
