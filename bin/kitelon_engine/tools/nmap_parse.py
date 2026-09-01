import re
import xml.etree.ElementTree as ET
from collections import namedtuple
from pathlib import Path

from kitelon_engine.context import ScanContext
from kitelon_engine.findings import Finding, FindingWriter

CVE_IN_TEXT = re.compile(r"(CVE-\d{4}-\d{4,})", re.IGNORECASE)
CVSS_AFTER_CVE = re.compile(r"(CVE-\d{4}-\d{4,})\s+([\d.]+)", re.IGNORECASE)

NmapService = namedtuple("NmapService", ("port", "service", "product"))


def parse_open_ports(xml_path: Path) -> list[int]:
    if not xml_path.is_file():
        return []
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return []
    ports: list[int] = []
    for port_el in root.findall(".//port"):
        state = port_el.find("state")
        if state is None or state.get("state") != "open":
            continue
        port_id = port_el.get("portid")
        if port_id and port_id.isdigit():
            ports.append(int(port_id))
    return sorted(set(ports))


def parse_nmap_services(xml_path: Path) -> list[NmapService]:
    if not xml_path.is_file():
        return []
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return []

    services: list[NmapService] = []
    for port_el in root.findall(".//port"):
        state = port_el.find("state")
        if state is None or state.get("state") != "open":
            continue
        port_id = port_el.get("portid")
        if not port_id or not port_id.isdigit():
            continue
        svc_el = port_el.find("service")
        service = (svc_el.get("name") if svc_el is not None else "") or ""
        product = (svc_el.get("product") if svc_el is not None else "") or ""
        services.append(NmapService(int(port_id), service.lower(), product))
    return services


def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def parse_os_guess(xml_path: Path) -> str | None:
    if not xml_path.is_file():
        return None
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return None

    best_name: str | None = None
    best_acc = -1
    for osmatch in root.findall(".//osmatch"):
        name = (osmatch.get("name") or "").strip()
        if not name:
            continue
        try:
            accuracy = int(osmatch.get("accuracy", "0"))
        except ValueError:
            accuracy = 0
        if accuracy > best_acc:
            best_acc = accuracy
            best_name = name[:120]
    return best_name


def _parse_vulners_script(script: ET.Element, hostname: str, seen: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    cpe = ""

    for table in script.findall("table"):
        table_key = (table.get("key") or "").strip()
        if table_key.startswith("cpe:"):
            cpe = table_key

        for entry in table.findall("table"):
            elems = {
                elem.get("key"): (elem.text or "").strip()
                for elem in entry.findall("elem")
                if elem.get("key")
            }
            cve_id = elems.get("id", "")
            if not cve_id.upper().startswith("CVE-"):
                continue
            cve_id = cve_id.upper()
            if cve_id in seen:
                continue
            seen.add(cve_id)

            try:
                cvss = float(elems.get("cvss") or "0")
            except ValueError:
                cvss = 0.0
            vuln_type = elems.get("type") or "cve"
            evidence = f"{cve_id} CVSS {cvss:.1f}"
            if cpe:
                evidence += f" ({cpe})"
            if vuln_type:
                evidence += f" [{vuln_type}]"

            findings.append(
                Finding(
                    severity=cvss_to_severity(cvss),
                    name=f"Known vulnerability {cve_id}",
                    hostname=hostname,
                    url=hostname,
                    evidence=evidence,
                    source="nmap-vulners",
                )
            )

    output = script.get("output") or ""
    for match in CVSS_AFTER_CVE.finditer(output):
        cve_id = match.group(1).upper()
        if cve_id in seen:
            continue
        seen.add(cve_id)
        try:
            cvss = float(match.group(2))
        except ValueError:
            cvss = 0.0
        findings.append(
            Finding(
                severity=cvss_to_severity(cvss),
                name=f"Known vulnerability {cve_id}",
                hostname=hostname,
                url=hostname,
                evidence=f"{cve_id} CVSS {cvss:.1f}",
                source="nmap-vulners",
            )
        )

    for cve_id in CVE_IN_TEXT.findall(output):
        cve_id = cve_id.upper()
        if cve_id in seen:
            continue
        seen.add(cve_id)
        findings.append(
            Finding(
                severity="info",
                name=f"Known vulnerability {cve_id}",
                hostname=hostname,
                url=hostname,
                evidence=cve_id,
                source="nmap-vulners",
            )
        )

    return findings


def parse_vulners_findings(xml_path: Path, hostname: str) -> list[Finding]:
    if not xml_path.is_file():
        return []
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return []

    seen: set[str] = set()
    findings: list[Finding] = []
    for script in root.findall(".//script[@id='vulners']"):
        findings.extend(_parse_vulners_script(script, hostname, seen))
    return findings


def import_nmap_enrichment(
    ctx: ScanContext,
    hostname: str,
    xml_path: Path,
    *,
    os_artifact: Path | None = None,
) -> tuple[str | None, int]:
    """Write OS artifact and emit vulners findings to findings.jsonl."""
    os_guess = parse_os_guess(xml_path)
    if os_guess and os_artifact is not None:
        os_artifact.parent.mkdir(parents=True, exist_ok=True)
        os_artifact.write_text(os_guess, encoding="utf-8")

    findings = parse_vulners_findings(xml_path, hostname)
    if findings:
        writer = FindingWriter(ctx.findings_path)
        writer.emit_many(findings)
        ctx.log(f"recorded {len(findings)} vulners CVE finding(s) for {hostname}")
    return os_guess, len(findings)
