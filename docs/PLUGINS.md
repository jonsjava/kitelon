# Kitelon plugins

Inventory of integrated plugins. Manifest: [`conf/plugins/registry.json`](../conf/plugins/registry.json). Runtime: [MODULARITY.md](MODULARITY.md). Vocabulary: [GLOSSARY.md](GLOSSARY.md).

## Recon pipeline (registry-driven)

| Plugin | Config | Addons | Packs | Wrapper |
|--------|--------|--------|-------|---------|
| Subfinder | `ENABLE_SUBFINDER` | — | — | `subfinder.py` |
| dnsx | `ENABLE_DNSX` | — | — | `dnsx.py` |
| dnsrecon | `ENABLE_DNSRECON` | — | — | `dnsrecon.py` |
| gau | `ENABLE_GAU` | — | — | `gau.py` |

## OSINT pipeline

| Plugin | Config | Addons | Packs | Wrapper |
|--------|--------|--------|-------|---------|
| WHOIS | always on in `osint` mode | — | — | `osint.py` |
| theHarvester | always on in `osint` mode | — | — | `osint.py` |
| metagoofil | `ENABLE_METAGOOFILE` | — | vendored clone | `metagoofil.py` |
| Shodan | `ENABLE_SHODAN` + API key | — | — | `shodan.py` |
| Censys | `ENABLE_CENSYS` + API keys | — | — | `censys.py` |

## Port / service pipeline

| Plugin | Config | Addons | Packs | Wrapper |
|--------|--------|--------|-------|---------|
| Nmap | always on | vulners NSE, OS detect | vulners.nse | `nmap.py` |
| Naabu | `ENABLE_NAABU` | — | — | `naabu.py` |
| Metasploit | `ENABLE_METASPLOIT` | auxiliary scanners | `scanners` | `metasploit.py` |
| enum4linux-ng | `ENABLE_ENUM4LINUX` | — | — | `smb.py` |
| smbmap | `ENABLE_SMBMAP` | — | — | `smb.py` |
| ssh-audit | `ENABLE_SSH_AUDIT` | — | vendored clone | `smb.py` |

### Metasploit scanner pack

Shipped: [`conf/packs/metasploit/scanners.json`](../conf/packs/metasploit/scanners.json). Edit port → MSF module lists without changing Python. MSF paths remain upstream **modules** (`auxiliary/scanner/...`).

## Web pipeline

| Plugin | Config | Addons | Packs | Wrapper |
|--------|--------|--------|-------|---------|
| httpx | `ENABLE_HTTPX` | — | — | `httpx.py` |
| webtech | `ENABLE_WEBTECH` | — | — | `webtech.py` |
| gowitness | `ENABLE_GOWITNESS` | — | — | `gowitness.py` |
| wafw00f | `ENABLE_WAFW00F` | — | — | `wafw00f.py` |
| Nuclei | `ENABLE_NUCLEI` | template sets | nuclei-templates | `nuclei.py` |
| katana | `ENABLE_KATANA` | — | — | `katana.py` |
| testssl.sh | `ENABLE_TESTSSL` | — | vendored clone | `testssl.py` |
| tlsx | `ENABLE_TLSX` | — | — | `tlsx.py` |
| Nikto | `ENABLE_NIKTO` | — | — | `nikto.py` |
| dirsearch | `ENABLE_DIRSEARCH` | — | web-brute-common | `gobuster.py` |
| gobuster | `ENABLE_GOBUSTER` | — | web-brute-common | `gobuster.py` |
| ffuf | `ENABLE_FFUF` | — | web-brute-common | `ffuf.py` |

## Content packs (today)

| Pack | Plugin | Path (current) | Notes |
|------|--------|----------------|-------|
| `scanners` | metasploit | `conf/packs/metasploit/scanners.json` | Default auxiliary scanner set |
| nuclei-templates | nuclei | `$PLUGINS_DIR/nuclei-templates` | Move to `packs/` in Phase B |
| web-brute-common | dirsearch/gobuster/ffuf | `$WORDLIST_DIR/web-brute-common.txt` | Move to `packs/` in Phase B |
| vulners.nse | nmap | nmap scripts dir | Installed by `install.sh` |

## Vendored clones (`$PLUGINS_DIR`)

Git checkouts used by plugins (not packs): testssl.sh, wafw00f, dirsearch, metagoofil, ssh-audit, enum4linux-ng. See [TOOLS.md](TOOLS.md).

## Optional external

| Plugin | Notes |
|--------|-------|
| OWASP ZAP | `web-deep` mode; external daemon — not in registry yet |
