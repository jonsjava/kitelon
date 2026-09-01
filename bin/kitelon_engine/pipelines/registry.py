from typing import Callable

from kitelon_engine.context import ScanContext
from kitelon_engine.pipelines import batch, batch_fast, discover, full_audit, osint, simple, webscan

PipelineFn = Callable[[ScanContext], int]

PIPELINES: dict[str, PipelineFn] = {
    "normal": simple.normal,
    "stealth": simple.stealth,
    "web": simple.web,
    "web-http": simple.web_http,
    "web-https": simple.web_https,
    "recon": simple.recon,
    "osint": osint.run,
    "discover": discover.run,
    "allports": simple.allports,
    "ports-only": simple.ports_only,
    "ports-quick": simple.ports_quick,
    "port": simple.port,
    "vuln": simple.vuln,
    "web-deep": webscan.run,
    "batch-ports": batch.batch_ports,
    "batch-web": batch.batch_web,
    "batch-webdeep": batch.batch_webdeep,
    "batch-vuln": batch.batch_vuln,
    "batch-ports-fast": batch_fast.run,
    "full-audit": full_audit.run,
}


def get_pipeline(mode: str) -> PipelineFn:
    key = (mode or "normal").lower().strip()
    if key not in PIPELINES:
        raise ValueError(f"unknown scan mode: {mode}")
    return PIPELINES[key]
