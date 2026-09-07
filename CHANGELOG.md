# Changelog

All notable changes to Kitelon are documented here.

## [Unreleased]

### Docker / CI
- Trivy publish scan ignores intended findings: Metasploit and Go-module test secrets (path-scoped `.trivyignore.yaml`), kernel header / pdfkit / dirsearch / scanner-module CVEs (`security/trivy-intended.rego`), and shipped Go tool binaries (`trivy.yaml`).
- ClamAV workflow chowns `/var/lib/clamav` to `clamav` after cache restore so `freshclam` can write temp files.

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
