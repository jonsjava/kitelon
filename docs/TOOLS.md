# Kitelon tool sources

Reference for every external tool Kitelon installs or invokes.  
Install path defaults: `/usr/share/kitelon/plugins`, Go binaries in `~/go/bin` → `/usr/local/bin`.

**Legend:** **Engine** = wired in `bin/kitelon_engine/tools/` and `pipelines/`; **Report** = post-scan import or PDF/HTML generation only.

---

## System packages (apt / dnf / pacman / brew)

| Tool | Source | Kitelon install | Notes |
|------|--------|-----------------|-------|
| nmap | https://nmap.org | apt/dnf/pacman/brew | **Engine**: port discovery, service scan, `vulners.nse` |
| nikto | https://github.com/sullo/nikto | apt (Debian) / optional (RHEL) | **Engine** `ENABLE_NIKTO` |
| whois | distro | apt/dnf/pacman/brew | **Engine** OSINT (`--osint` / `-o`) |
| theHarvester | https://github.com/laramies/theHarvester | apt optional + pip | **Engine** OSINT |
| wkhtmltopdf | https://wkhtmltopdf.org | apt/brew | **Report**: `report.py` / pdfkit |
| metasploit | https://github.com/rapid7/metasploit-framework | omnibus installer / brew / pacman | **Engine** `ENABLE_METASPLOIT`: auxiliary scanners via `msfconsole` |
| enum4linux-ng | https://github.com/cddmp/enum4linux-ng | apt optional; else git+pip | **Engine** `ENABLE_ENUM4LINUX` (port 445) |
| gobuster | https://github.com/OJ/gobuster | **go install** (preferred) or apt fallback | **Engine** `ENABLE_GOBUSTER`: dir brute-force fallback |

---

## Go tools (`go install` @latest)

Go **1.27.0** is installed from [go.dev](https://go.dev/doc/install) into `/usr/local/go`.

| Tool | Repository | Engine flag |
|------|------------|-------------|
| nuclei | https://github.com/projectdiscovery/nuclei | `ENABLE_NUCLEI` |
| gowitness | https://github.com/sensepost/gowitness | `ENABLE_GOWITNESS` |
| httpx | https://github.com/projectdiscovery/httpx | `ENABLE_HTTPX` |
| subfinder | https://github.com/projectdiscovery/subfinder | `ENABLE_SUBFINDER` |
| ffuf | https://github.com/ffuf/ffuf | `ENABLE_FFUF` |
| naabu | https://github.com/projectdiscovery/naabu | `ENABLE_NAABU` |
| dnsx | https://github.com/projectdiscovery/dnsx | `ENABLE_DNSX` |
| katana | https://github.com/projectdiscovery/katana | `ENABLE_KATANA` |
| tlsx | https://github.com/projectdiscovery/tlsx | `ENABLE_TLSX` |
| gobuster | https://github.com/OJ/gobuster | `ENABLE_GOBUSTER` |

### Metasploit auxiliary scanners

After nmap, Kitelon imports the host into the MSF workspace DB and runs **auxiliary/scanner** modules matched to open ports (SMB, HTTP, MySQL, RDP, etc.). Findings land in `findings.jsonl` and artifacts under `tools/metasploit/<host>/`.

| Config key | Default | Meaning |
|------------|---------|---------|
| `ENABLE_METASPLOIT` | `1` | Run MSF auxiliary scanners (skipped in `stealth` mode) |
| `MSF_MODULE_TIMEOUT` | `420` | Seconds per module |
| `MSF_MAX_MODULES` | `12` | Cap modules per host |

---

## Python pip (core)

| Package | Use |
|---------|-----|
| webtech | **Engine** `ENABLE_WEBTECH`: primary web tech fingerprint |
| wafw00f | **Engine** `ENABLE_WAFW00F` (installed from git clone + pip) |
| smbmap | **Engine** `ENABLE_SMBMAP` |
| fastapi / uvicorn / psycopg / croniter / cmd2 | Kitelon API, DB, CLI, worker |
| pdfkit | PDF report export (with wkhtmltopdf) |
| dnspython, requests, tldextract, colorama, urllib3 | Engine / loot helpers |

---

## Git plugins (`$PLUGINS_DIR`)

| Directory | Repository | Notes |
|-----------|------------|-------|
| testssl.sh | https://github.com/drwetter/testssl.sh | **Engine** `ENABLE_TESTSSL`; wrapper at `/usr/local/bin/testssl.sh` |
| wafw00f | https://github.com/EnableSecurity/wafw00f | pip install from clone |
| dirsearch | https://github.com/maurosoria/dirsearch (**v0.4.3**) | **Engine** `ENABLE_DIRSEARCH` |
| ssh-audit | https://github.com/jtesta/ssh-audit | **Engine** `ENABLE_SSH_AUDIT` (port 22) |
| enum4linux-ng | https://github.com/cddmp/enum4linux-ng | apt or git fallback: see above |
| nuclei-templates | updated by `nuclei -update-templates` during install | `NUCLEI_TEMPLATES` path |

---

## Downloads

| Asset | URL | Purpose |
|-------|-----|---------|
| vulners.nse | https://github.com/vulnersCom/nmap-vulners | Nmap CVE script (`ENABLE_VULNERS`) |
| web-brute-common.txt | SecLists `Discovery/Web-Content/common.txt` | dirsearch / gobuster / ffuf wordlist |

---

## Optional / external (not installed by default)

| Tool | Notes |
|------|-------|
| OWASP ZAP | `bin/zap-scan.py` + `web-deep` mode. Upstream example by aine-rb (Sopra Steria), adapted for Kitelon. Requires external ZAP daemon, `zapv2` pip, and an API key from ZAP → Tools → Options → API |

---

## Install notes

| Item | Detail |
|------|--------|
| wafw00f | apt package removed when present; EnableSecurity git + pip is canonical |
| testssl.sh | git clone + bash wrapper; repo script must not be overwritten |
| gobuster | `go install …/gobuster/v3@latest`; apt v3.0.1 tarball is too old for `dir` subcommand |
| dirsearch | pinned to git tag **v0.4.3** (v0.5.x has breaking CLI changes) |
| gowitness | v3 CLI: `gowitness scan single --write-none` |

Re-run `sudo bash install.sh force` after upgrading to refresh git/pip/go tools.
