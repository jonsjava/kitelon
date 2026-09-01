"""Normalized finding records."""


import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


SEVERITIES = {"critical", "high", "medium", "low", "info"}


@dataclass
class Finding:
    severity: str
    name: str
    hostname: str
    url: str = ""
    evidence: str = ""
    source: str = ""
    source_file: str = "findings.jsonl"
    cve: str = ""
    cwe: str = ""
    tags: list[str] | None = None
    metadata: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        self.severity = self.severity.lower()
        if self.severity not in SEVERITIES:
            self.severity = "info"
        if not self.url:
            self.url = self.hostname
        if self.tags is None:
            self.tags = []

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if not data.get("cve"):
            data.pop("cve", None)
        if not data.get("cwe"):
            data.pop("cwe", None)
        if not data.get("tags"):
            data.pop("tags", None)
        if not data.get("metadata"):
            data.pop("metadata", None)
        return data

    def to_jsonl(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


class FindingWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, finding: Finding) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(finding.to_jsonl() + "\n")

    def emit_kv(self, **fields: Any) -> None:
        self.emit(Finding(**fields))

    def emit_many(self, findings: list[Finding]) -> None:
        for item in findings:
            self.emit(item)


def parse_findings_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows
