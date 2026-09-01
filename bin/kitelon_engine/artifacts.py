"""Manifest and artifact helpers."""


import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kitelon_engine.context import ScanContext


class Manifest:
    def __init__(self, ctx: ScanContext) -> None:
        self.ctx = ctx
        self.data: dict[str, Any] = self._load_or_new()

    def _load_or_new(self) -> dict[str, Any]:
        path = self.ctx.manifest_path
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        return {
            "scan_id": self.ctx.scan_id,
            "target": self.ctx.target,
            "mode": self.ctx.mode,
            "workspace": self.ctx.workspace,
            "options": self.ctx.options,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "steps": [],
        }

    def save(self) -> None:
        self.ctx.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        self.ctx.manifest_path.write_text(
            json.dumps(self.data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def step_done(self, step_id: str, artifact: str | None = None) -> None:
        steps: list[dict[str, Any]] = self.data.setdefault("steps", [])
        entry = {"id": step_id, "status": "done", "at": datetime.now(timezone.utc).isoformat()}
        if artifact:
            entry["artifact"] = artifact
        steps.append(entry)
        self.save()

    def is_step_done(self, step_id: str) -> bool:
        if not self.ctx.resume:
            return False
        for step in self.data.get("steps", []):
            if step.get("id") == step_id and step.get("status") == "done":
                return True
        return False

    def artifact_path(self, *parts: str) -> Path:
        path = self.ctx.artifacts_dir.joinpath(*parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def should_skip(self, step_id: str, output: Path) -> bool:
        if not self.ctx.resume:
            return False
        if self.is_step_done(step_id):
            return True
        return output.is_file() and output.stat().st_size > 0
