import http.client
import urllib.error
import urllib.request

from kitelon_engine.context import ScanContext
from kitelon_engine.findings import Finding, FindingWriter

_NETWORK_ERRORS = (
    urllib.error.URLError,
    TimeoutError,
    ConnectionError,
    http.client.HTTPException,
    OSError,
)


def _fetch_headers(url: str, timeout: int = 10) -> dict[str, str]:
    for method in ("HEAD", "GET"):
        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", "Kitelon/1.0")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                if method == "GET":
                    resp.read(1)
                return headers
        except urllib.error.HTTPError as exc:
            if exc.headers:
                return {k.lower(): v for k, v in exc.headers.items()}
            if method == "HEAD" and exc.code in (405, 501):
                continue
            return {}
        except _NETWORK_ERRORS:
            continue
    return {}


def _note(
    writer: FindingWriter,
    findings: list[Finding],
    *,
    severity: str,
    name: str,
    hostname: str,
    url: str,
    evidence: str,
) -> None:
    row = Finding(
        severity=severity,
        name=name,
        hostname=hostname,
        url=url,
        evidence=evidence,
        source="header_check",
    )
    findings.append(row)
    writer.emit(row)


def check_headers(ctx: ScanContext, url: str, hostname: str) -> list[Finding]:
    headers = _fetch_headers(url)
    if not headers:
        return []

    findings: list[Finding] = []
    writer = FindingWriter(ctx.findings_path)

    if "strict-transport-security" not in headers and url.startswith("https"):
        _note(
            writer,
            findings,
            severity="medium",
            name="Missing Strict-Transport-Security",
            hostname=hostname,
            url=url,
            evidence="HSTS header not present on HTTPS response",
        )

    if "content-security-policy" not in headers:
        _note(
            writer,
            findings,
            severity="low",
            name="Missing Content-Security-Policy",
            hostname=hostname,
            url=url,
            evidence="CSP header not present",
        )

    if not headers.get("x-frame-options", "").lower():
        _note(
            writer,
            findings,
            severity="low",
            name="Missing X-Frame-Options",
            hostname=hostname,
            url=url,
            evidence="Clickjacking protection header absent",
        )

    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        if "httponly" not in set_cookie.lower():
            _note(
                writer,
                findings,
                severity="low",
                name="Cookie missing HttpOnly flag",
                hostname=hostname,
                url=url,
                evidence=set_cookie[:200],
            )
        if url.startswith("https") and "secure" not in set_cookie.lower():
            _note(
                writer,
                findings,
                severity="medium",
                name="Secure cookie not set on HTTPS",
                hostname=hostname,
                url=url,
                evidence=set_cookie[:200],
            )

    acao = headers.get("access-control-allow-origin", "")
    if acao == "*":
        _note(
            writer,
            findings,
            severity="low",
            name="CORS Allow-Origin wildcard",
            hostname=hostname,
            url=url,
            evidence=f"Access-Control-Allow-Origin: {acao}",
        )

    if "x-powered-by" in headers:
        _note(
            writer,
            findings,
            severity="info",
            name="Server technology disclosure",
            hostname=hostname,
            url=url,
            evidence=f"X-Powered-By: {headers['x-powered-by']}",
        )

    return findings
