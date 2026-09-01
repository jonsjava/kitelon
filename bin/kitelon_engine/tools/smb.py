"""SMB enumeration (enum4linux-ng, smbmap)."""


import json
import re
from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.findings import Finding, FindingWriter
from kitelon_engine.tools.base import run_cmd, which


def run_enum4linux(ctx: ScanContext, host: str, output: Path) -> bool:
    tool = which("enum4linux-ng")
    if not tool:
        ctx.log("enum4linux-ng not found, skip SMB enum")
        return False

    json_out = output.with_suffix(".json")
    args = [tool, "-A", "-oJ", str(json_out), host]
    ctx.log(f"running enum4linux-ng on {host}")
    run_cmd(args, timeout=1800)
    output.parent.mkdir(parents=True, exist_ok=True)
    if json_out.is_file():
        output.write_text(json_out.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
        _import_enum4linux(ctx, host, json_out)
        return True
    return False


def _import_enum4linux(ctx: ScanContext, host: str, path: Path) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return
    writer = FindingWriter(ctx.findings_path)
    for key in ("shares", "users", "groups"):
        items = data.get(key, [])
        if not isinstance(items, list):
            continue
        for item in items[:50]:
            label = json.dumps(item)[:300] if isinstance(item, dict) else str(item)[:300]
            writer.emit(
                Finding(
                    severity="info",
                    name=f"SMB {key}: {label[:120]}",
                    hostname=host,
                    evidence=label,
                    source="enum4linux-ng",
                    source_file=path.name,
                )
            )


def run_smbmap(ctx: ScanContext, host: str, output: Path) -> bool:
    smbmap = which("smbmap")
    if not smbmap:
        ctx.log("smbmap not found, skip")
        return False

    args = [smbmap, "-H", host]
    ctx.log(f"running smbmap on {host}")
    proc = run_cmd(args, timeout=900)
    output.parent.mkdir(parents=True, exist_ok=True)
    text = proc.stdout + proc.stderr
    output.write_text(text, encoding="utf-8", errors="replace")
    writer = FindingWriter(ctx.findings_path)
    for line in text.splitlines():
        if "READ" in line or "WRITE" in line:
            writer.emit(
                Finding(
                    severity="medium",
                    name=f"smbmap share: {line.strip()[:160]}",
                    hostname=host,
                    evidence=line.strip(),
                    source="smbmap",
                    source_file=output.name,
                )
            )
    return True


def run_ssh_audit(ctx: ScanContext, host: str, port: int, output: Path) -> bool:
    plugins = Path(ctx.options.get("install_dir", ctx.install_dir)) / "plugins"
    ssh_audit = plugins / "ssh-audit" / "ssh-audit.py"
    if not ssh_audit.is_file():
        ssh_audit_py = which("ssh-audit")
        if ssh_audit_py:
            ssh_audit = Path(ssh_audit_py)
        else:
            ctx.log("ssh-audit not found, skip")
            return False

    target = f"{host}:{port}"
    args = ["python3", str(ssh_audit), target]
    ctx.log(f"running ssh-audit on {target}")
    proc = run_cmd(args, timeout=300)
    output.parent.mkdir(parents=True, exist_ok=True)
    text = proc.stdout + proc.stderr
    output.write_text(text, encoding="utf-8", errors="replace")
    writer = FindingWriter(ctx.findings_path)
    for line in text.splitlines():
        lower = line.lower()
        if any(k in lower for k in ("fail", "weak", "vulnerable", "deprecated", "[fail]")):
            writer.emit(
                Finding(
                    severity="medium",
                    name=f"ssh-audit: {line.strip()[:160]}",
                    hostname=host,
                    url=target,
                    evidence=line.strip(),
                    source="ssh-audit",
                    source_file=output.name,
                )
            )
    return True
