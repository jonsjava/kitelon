# Changelog

All notable changes to Kitelon are documented here.

## [Unreleased]

### Install / Docker
- Upgrade pip `cryptography` to >=50.0.0 (and `pyOpenSSL` with it) after plugin requirements so Trivy no longer fails publish on CVE-2026-69247, CVE-2026-69249, and GHSA-537c-gmf6-5ccf.
- Fix stale `*.dist-info` prune regex so leftover pip METADATA dirs are actually removed.

## [0.4.0] - 2026-09-07

### Web UI
- Sleek dark theme refresh (evolved custom CSS; no JS framework bundler).
- Workspaces home: summary strip, collapsible create/import panel, severity donut charts (ring = findings by severity, center = risk score), 30s incremental stat refresh.
- Jobs page: incremental table updates on poll (status pills, no full tbody rebuild); running-row pulse animation.
- Shared header nav via `KitelonUI.renderNav()` across all pages.
- Chart.js doughnut helper in `web/static/charts.js`.
- Fix Web UI API key loading: always source `/root/.kitelon_api_keys.conf`; unset empty `WEB_API_KEY` before startup.

## [0.3.9] - 2026-09-06

### Install / Docker
- Reorder `install.sh`: loot workspace layout and theHarvester pip run after `python3`/`pip` are installed.
- Kali-only apt for `theharvester`; Ubuntu uses pip. Skip `enum4linux-ng` apt unless the package exists (Kali or `apt-cache show`).
- PEP 668: drop pip self-upgrade on Debian/Ubuntu; use `--ignore-installed` for dirsearch and enum4linux-ng requirements.
- Skip `systemctl daemon-reload` when `KITELON_DOCKER=1` or running inside Docker.
- Pin Go 1.27.0 tarball SHA256 for linux/darwin amd64 and arm64 (fallback to go.dev JSON for other arches).
- Upgrade-safe plugin/git installs: fetch+reset fallback, wrapper helpers that replace dangling symlinks (testssl.sh, enum4linux-ng).
- Go tools install to `$GOPATH/bin` and symlink into PATH (fixes re-install when `/usr/local/bin` already has symlinks).

### CI
- Document `main` branch protection: PRs required; `test`, `vet`, and `clamav` must pass before merge.

## [0.3.8] - 2026-09-06

### Docker / CI
- Publish `jonsjava/kitelon` to Docker Hub on `v*` tags after `test`, `vet`, and `clamav` succeed (reusable jobs; image build does not start until they pass).
- Weekly rebuild workflow: Sunday 06:00 UTC `apt full-upgrade`, Trivy scan, push `latest` and `weekly-YYYY-MM-DD`.
- Trivy HIGH/CRITICAL gate with intended-finding filters: path-scoped `.trivyignore.yaml` (Metasploit / Go-module test secrets), `security/trivy-intended.rego` (`linux-libc-dev`, pdfkit, dirsearch crates, scanner modules), and `trivy.yaml` skip-files for pinned Go binaries.
- ClamAV workflow chowns `/var/lib/clamav` after cache restore so `freshclam` can write temp files.
- GitHub Actions on Node 24 runtimes (`checkout@v5`, `cache@v5`, `setup-python@v6`, Docker actions `@v4`/`@v7`, `vet-action@v1.1.12`).

### Docker image
- Dedicated `kitelon` Metasploit DB user; `install.sh` bootstraps that user in containers so cached layers and older tags initialize `msfdb` correctly.

## [0.3.7] - 2026-09-06

### CI
- GitHub Actions `test` (pytest), `vet` (SafeDep), and `clamav` (ClamAV) workflows with README badges.
- Docker Hub publish workflow on version tags (Trivy scan before push).

## [0.3.6] - 2026-09-06

### Modularity (plugin / addon / pack)
- Plugin registry: `conf/plugins/registry.json`, `bin/kitelon_engine/plugin_registry.py`
- Pack loader: `conf/packs/`, `bin/kitelon_engine/pack_loader.py`
- Metasploit default scanner **pack**: `conf/packs/metasploit/scanners.json`
- Recon pipeline driven by registry + `pipeline_hooks/recon.py` (respects per-plugin `ENABLE_*` flags)
- Docs: `GLOSSARY.md`, `MODULARITY.md`, `PLUGINS.md`; updated `TOOLS.md`, `PIPELINES.md`, `DEVELOPMENT.md`, `README.md`

### Storage
- Artifact retrieval validates stored size against `LOOT_ARTIFACT_MAX_BYTES`
- `store_file_from_disk` canonicalizes paths before computing relative paths

### Workspace
- Workspace alias normalization applies Unicode NFC before slash/space folding

### Tests
- `test_pack_loader.py`, `test_plugin_registry.py`, `test_recon_hooks.py`

## [0.3.5] - 2026-09-04

### OSINT / recon
- Engine hooks: **dnsrecon**, **gau**, optional **metagoofil**, **Shodan**, **Censys** (upstream tools only)
- Conservative defaults in `kitelon.conf`; raise limits via config or `--preset osint-deep`
- Presets: `osint-conservative`, `osint-deep`
- Loot artifacts under `artifacts/recon/`: `dnsrecon.json`, `gau-urls.txt`, `shodan.json`, `censys.json`, `metagoofil/`

### Install
- `install.sh`: dnsrecon (apt), metagoofil git plugin, gau (Go), `shodan` + `censys` pip packages

### CLI
- `kitelon` bash driver: forward `-o`, `-re`, and `--preset` to the engine
- `kitelon-cli`: scan flags use short forms (`-o`, `-re`, `-pr`, …); descriptive tab completion for targets, modes, presets, workspaces, and ports; expanded help and README coverage

## [0.3.4] - 2026-09-01

Initial public release (0.3.4).

### Platform
- CLI `kitelon` / `kitelon-cli`, Python package `kitelon_engine`, install path `/usr/share/kitelon`
- Env `KITELON_*`, systemd `kitelon-worker*`, PostgreSQL database `kitelon`
- `VERSION` file as the single source for the CLI and API version string
- Authorized-use policy: [docs/LEGAL.md](docs/LEGAL.md), acknowledgement prompt, `bin/kitelon_ui.sh`, `bin/kitelon_authorization.sh`

### Scan engine
- Python pipelines in `bin/kitelon_engine/` invoked by `bin/kitelon_scan.py`
- Workspace is required. Queue, worker, and engine reject scans without one; loot is written under `loot/workspace/<alias>/`
- Loot layout: `manifest.json`, `findings.jsonl`, `artifacts/`
- Presets under `conf/presets/`; `ENABLE_*` tool toggles in config
- Engine tools include nmap, httpx, nuclei, ffuf, webtech, gowitness, naabu, dnsx, katana, tlsx, nikto, wafw00f, Metasploit auxiliary modules, testssl.sh

### Data, jobs, and UI
- PostgreSQL for hosts, findings, artifacts, job queue, and schedules
- JSON API and Web UI (`127.0.0.1:8080`): workspaces, jobs, schedules, reports, ZIP export/import
- Split or combined workers (`kitelon-worker`, `kitelon-worker-scan`, `kitelon-worker-post`)
- Rotating logs under `/var/log/kitelon`
- Docker stack: `Dockerfile`, `docker-compose.yml`, `docker/entrypoint.sh`

### Operator notes
- README documents project motivation and independence from Sn1per
- `kitelon workspaces create <alias>` and `kitelon jobs list --limit` treat extra args as command arguments, not scan flags
- `ensure_workspace` creates the loot layout so new workspaces are not pruned on list
- `GET /api/v1/workspaces` syncs from disk without deleting workspace rows
- API requires `WEB_API_KEY` on all binds (generated on first start if missing); job scan args are allowlisted
- Workspace loot paths are rebuilt from the alias and confined under `loot/workspace/`
- Local tests: `PYTHONPATH=bin pytest tests/`
