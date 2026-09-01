import subprocess
import sys
from pathlib import Path

from kitelon_engine.context import ScanContext


def _log(msg: str) -> None:
    print(f"[kitelon-db] {msg}", file=sys.stderr)


def _is_valid_testssl_script(path: Path) -> bool:
    try:
        line_count = sum(1 for _ in path.open(encoding="utf-8", errors="replace"))
    except OSError:
        return False
    # Real testssl.sh is a large script; the PATH wrapper is ~2 lines.
    return line_count >= 100


def restore_testssl_script(install_dir: Path) -> bool:
    """Restore plugins/testssl.sh/testssl.sh if overwritten by the wrapper."""
    install_dir = Path(install_dir)
    repo_script = install_dir / "plugins/testssl.sh/testssl.sh"
    repo_dir = repo_script.parent

    if _is_valid_testssl_script(repo_script):
        return True
    if not (repo_dir / ".git").is_dir():
        return False

    _log("testssl.sh script corrupted, restoring from git...")
    try:
        subprocess.run(
            ["git", "-C", str(repo_dir), "checkout", "--", "testssl.sh"],
            check=False,
            capture_output=True,
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if _is_valid_testssl_script(repo_script):
        repo_script.chmod(0o755)
        _log(f"restored testssl.sh from git ({repo_script})")
        return True
    return False


def find_testssl_binary(install_dir: Path | None = None) -> Path | None:
    install_dir = Path(install_dir or "/usr/share/kitelon")
    repo_script = install_dir / "plugins/testssl.sh/testssl.sh"
    if repo_script.is_file() and _is_valid_testssl_script(repo_script):
        return repo_script
    if restore_testssl_script(install_dir) and _is_valid_testssl_script(repo_script):
        return repo_script
    if repo_script.is_file():
        _log(
            "testssl.sh is corrupted (wrapper loop); run: "
            "sudo bash install.sh force"
        )
    return None


def run_testssl(ctx: ScanContext, host: str, port: int, output_json: Path) -> bool:
    from kitelon_engine.tools.base import run_cmd

    testssl_bin = find_testssl_binary(ctx.install_dir)
    if not testssl_bin:
        ctx.log("testssl.sh not installed; run: sudo bash install.sh force")
        return False

    log_out = output_json.with_suffix(".log")
    args = [
        "bash",
        str(testssl_bin),
        "--quiet",
        "--color",
        "0",
        "--warnings",
        "off",
        "--jsonfile-pretty",
        str(output_json),
        "--logfile",
        str(log_out),
        f"{host}:{port}",
    ]
    ctx.log(f"running testssl on {host}:{port}")
    proc = run_cmd(args, timeout=3600)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    return proc.returncode == 0 and output_json.is_file()
