

from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.tools.base import run_cmd, which


def capture_screenshot(ctx: ScanContext, url: str, output: Path) -> bool:
    gowitness = which("gowitness")
    if not gowitness:
        ctx.log("gowitness not found, skip screenshot")
        return False

    output.parent.mkdir(parents=True, exist_ok=True)
    args = [
        gowitness,
        "scan",
        "single",
        "--url",
        url,
        "--screenshot-path",
        str(output.parent),
        "--write-none",
        "--timeout",
        "45",
    ]
    ctx.log(f"capturing screenshot for {url}")
    run_cmd(args, timeout=120)
    stem = output.stem
    for candidate in output.parent.glob(f"*{stem}*"):
        if candidate.suffix.lower() in (".png", ".jpg", ".jpeg"):
            if candidate != output:
                candidate.rename(output)
            return output.is_file()
    for png in output.parent.glob("*.png"):
        png.rename(output)
        return True
    return output.is_file()
