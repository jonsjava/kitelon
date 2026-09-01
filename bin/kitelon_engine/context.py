import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def normalize_workspace_name(name: str) -> str:
    from kitelon_db import normalize_workspace_alias

    return normalize_workspace_alias(name)


@dataclass
class ScanContext:
    install_dir: Path
    target: str
    mode: str
    workspace: str
    options: dict[str, Any] = field(default_factory=dict)
    job_id: int | None = None
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def __post_init__(self) -> None:
        self.target = self.target.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
        if not self.workspace or not str(self.workspace).strip():
            raise ValueError("workspace required")
        self.workspace = normalize_workspace_name(self.workspace)

    @property
    def loot_root(self) -> Path:
        return self.install_dir / "loot" / "workspace" / self.workspace

    @property
    def artifacts_dir(self) -> Path:
        return self.loot_root / "artifacts"

    @property
    def findings_path(self) -> Path:
        return self.loot_root / "findings.jsonl"

    @property
    def manifest_path(self) -> Path:
        return self.loot_root / "manifest.json"

    @property
    def scan_log_path(self) -> Path:
        return self.loot_root / "scan.log"

    @property
    def resume(self) -> bool:
        return bool(self.options.get("resume"))

    @property
    def port(self) -> int | None:
        raw = self.options.get("port")
        if raw in (None, ""):
            return None
        return int(raw)

    @property
    def threads(self) -> int:
        return int(self.options.get("threads", 10))

    def ensure_dirs(self) -> None:
        for sub in (
            self.artifacts_dir / "nmap",
            self.artifacts_dir / "ports",
            self.artifacts_dir / "web",
            self.artifacts_dir / "ssl",
            self.artifacts_dir / "screenshots",
            self.artifacts_dir / "recon",
            self.artifacts_dir / "tools",
        ):
            sub.mkdir(parents=True, exist_ok=True)

    def log(self, message: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        line = f"[{ts}] {message}\n"
        self.scan_log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.scan_log_path.open("a", encoding="utf-8") as handle:
            handle.write(line)
        print(line, end="")
        try:
            from kitelon_log import get_logger

            get_logger("engine").info(
                "workspace=%s target=%s scan=%s %s",
                self.workspace or "-",
                self.target,
                self.scan_id,
                message,
            )
        except ImportError:
            pass


def default_install_dir() -> Path:
    env = os.environ.get("KITELON_INSTALL_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent.parent
