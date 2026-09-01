# Kitelon scan pipelines

The scan engine lives in `bin/kitelon_engine/` and runs through `bin/kitelon_scan.py` or `kitelon -t TARGET -w WORKSPACE`. Each **mode** maps to a handler in the pipeline registry (`bin/kitelon_engine/pipelines/registry.py`).

## Loot layout

```
loot/workspace/<alias>/
  manifest.json       # scan metadata + completed steps (resume)
  findings.jsonl      # canonical vulnerability records
  scan.log
  artifacts/
    nmap/<host>.xml
    ports/<host>.json
    web/<host>/...
    ssl/<host>-<port>.json
    recon/...
    tools/ffuf/...
    tools/katana/...
    tools/naabu/...
    screenshots/...
  reports/              # generated HTML/CSV/PDF
```

## Scan modes

| Mode | Handler | Behaviour |
|------|---------|-----------|
| `normal` | `simple.normal` | Optional recon/OSINT, port discovery, web on 80/443 |
| `stealth` | `simple.stealth` | Reduced threads, lighter port scan, single web port |
| `web` | `simple.web` | HTTP/HTTPS web stack only |
| `web-deep` | `webscan.run` | Web stack + optional ZAP |
| `web-http` / `web-https` | `simple.web_http` / `simple.web_https` | Single-port web stack |
| `recon` | `simple.recon` | Subdomain enum + light port scan |
| `osint` | `osint.run` | WHOIS + theHarvester |
| `discover` | `discover.run` | CIDR discovery, then normal subset per host |
| `allports` | `simple.allports` | nmap `-p-` then web on 80/443 |
| `ports-only` | `simple.ports_only` | Full port scan, no follow-on modules |
| `ports-quick` | `simple.ports_quick` | Light port scan only |
| `port` | `simple.port` | Single-port nmap |
| `vuln` | `simple.vuln` | httpx + nuclei on 80/443 |
| `batch-ports` | `batch.batch_ports` | All-port scan from `-f` target file |
| `batch-web` | `batch.batch_web` | Web scan from target file |
| `batch-webdeep` | `batch.batch_webdeep` | Deep web scan from target file |
| `batch-vuln` | `batch.batch_vuln` | Vuln scan from target file |
| `batch-ports-fast` | `batch_fast.run` | Fast multi-target port scan from file |
| `full-audit` | `full_audit.run` | OSINT + recon + web-deep + vuln |

## Options

| Flag | Effect |
|------|--------|
| `-rr` / `--resume` | Skip steps recorded in `manifest.json` or with existing artifacts |
| `-o` / `--osint` | Run OSINT modules during `normal` |
| `-re` / `--recon` | Run subdomain recon during `normal` |
| `-fp` / `--full-port` | Full port scan during `normal` |
| `ENABLE_VULNERS` / `ENABLE_OS_DETECT` | nmap `vulners.nse` CVE findings and `-O` OS fingerprint (default on; off in stealth) |
| `--testssl` | Force testssl on HTTPS |
| `--ffuf` | Enable ffuf path discovery (also `ENABLE_FFUF=1`) |
| `--preset` | Load overrides from `conf/presets/<name>.conf` |
| `-p` / `--port` | Limit to one port (`port`, `web-http`, `web-https`) |
| `-f` / `--target-file` | Target list for `batch-*` modes |

## Findings

Findings are written to `findings.jsonl` as JSON lines:

```json
{"severity":"high","name":"...","hostname":"example.com","url":"https://example.com/","evidence":"...","source":"nuclei","source_file":"findings.jsonl"}
```

`kitelon_loot.py` imports these into PostgreSQL on post-scan `loot_process` jobs.

## Passive checks

HTTP security header analysis is in `bin/kitelon_engine/checks/headers.py` (HSTS, CSP, cookies, CORS, X-Frame-Options).

## Tool wrappers

Subprocess wrappers live in `bin/kitelon_engine/tools/`:

| Wrapper | Config toggle | Notes |
|---------|---------------|-------|
| nmap, httpx, nuclei, subfinder, testssl, wafw00f | `ENABLE_*` | Core web/port pipeline |
| gobuster/dirsearch | `ENABLE_DIRSEARCH`, `ENABLE_GOBUSTER` | Path brute |
| ffuf | `ENABLE_FFUF` / `--ffuf` | JSON hits → `discovered_urls` |
| webtech | `ENABLE_WEBTECH` | Web tech fingerprint |
| gowitness | `ENABLE_GOWITNESS` | Screenshots |
| nikto | `ENABLE_NIKTO` | Web vuln scan |
| naabu, dnsx, katana, tlsx | `ENABLE_NAABU`, etc. | Optional PD toolchain |
| enum4linux-ng, smbmap, ssh-audit | SMB/SSH passes | When ports 445/22 open |
| ZAP | `web-deep` mode | JSON → `findings.jsonl` |

Presets: `conf/presets/{normal,stealth,web}.conf`. See [DEVELOPMENT.md](DEVELOPMENT.md) for local pytest.
