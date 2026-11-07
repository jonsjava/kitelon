# Changelog

All notable changes to Kitelon are documented here.

## [0.6.0] - 2026-11-06

### Upgrades
- `install.sh force` and `kitelon -u` drain the job queue before replacing files (`kitelon -u` drains before its `git pull`, since the pull itself replaces the running code when the install directory is the checkout): it pauses the queue, waits for running scans (worker jobs and direct CLI scans) to finish, stops the worker units, installs, then restarts them and resumes the queue, including when the install fails. New flags: `--drain-timeout SEC` (abort with nothing changed), `--force-stop` (interrupt running scans; they're requeued and resume), `--no-drain` (previous behavior).
- An upgrade leaves a queue that was already paused (e.g. by `kitelon upgrade pause`) paused, and keeps the queue paused if database migrations didn't run.
- `--force-stop` also stops a running `kitelon-worker-cron.service` tick (its scan is requeued) and direct CLI scans (re-run them with `-rr`). `--drain-timeout` must be a number of seconds.
- New `kitelon upgrade status|pause|resume|drain|is-paused|stop-local` command and `upgrade status|pause|resume` in kitelon-cli (`bin/kitelon_upgrade.py`).
- Queue pause is stored in PostgreSQL when the database is enabled, otherwise in `/var/lib/kitelon/paused` (`KITELON_PAUSE_FILE`). While paused, queued and newly enqueued jobs get the new `held` status, so no worker (including pre-0.6.0 workers) claims them. Direct scans (`kitelon -t` and `kitelon-cli scan --sync`) refuse to start, and running ones hold up the drain. Pausing waits for in-flight enqueues so none slips in as `pending`.
- `kitelon upgrade` exits 64 on bad arguments (previously argparse's 2, which callers read as "drain timed out"). An interrupted drain only resumes a pause it made.

### Jobs
- Interrupted jobs are requeued instead of failed: `recover` requeues a running job whose heartbeat is older than `WORKER_STALE_MINUTES` (default 10), or, for a job claimed on the same host, whose process has exited (after a 2-minute grace). A job that is still heartbeating is never touched, however long it runs, so `recover` no longer kills healthy long scans after 180 minutes (`WORKER_STUCK_MINUTES` is gone). Scan jobs come back resuming (`-rr`) and skip finished steps. A job is marked failed after 3 attempts.
- `recover` never signals a PID it can't verify as this job's process on this host (`jobs.worker_host` plus the process command line), so it can't kill an unrelated process that reuses the number, e.g. from the Docker recover sidecar.
- Each run owns its job: result, heartbeat and requeue writes only apply to the run that claimed it. If `recover` requeues a job while its old run is still going (e.g. after a long database outage), the old run is stopped on its next heartbeat and its result is discarded, so a scan never runs twice at once.
- The resume flag is stored separately from a job's scan arguments, so a manual retry starts a fresh scan, and jobs created with `options` resume correctly.
- Migrations `005_job_resilience` (`jobs.heartbeat_at`, `jobs.attempts`, `kitelon_settings` table) and `006_job_owner` (`jobs.worker_host`). Run `sudo kitelon db migrate` (the installer does this). Workers wait, without running jobs, until migrations are applied.
- `held` jobs can be edited, retried and cancelled like `pending` ones, including Edit in the web UI. The API returns a new job's real status (`held` while paused) instead of always `pending`.

### Worker
- Workers write a per-job heartbeat every 30s while a job runs (`WORKER_HEARTBEAT_SEC`).
- On SIGTERM/SIGINT the worker (including a `run-once` cron tick) stops claiming jobs, stops the running jobs' processes, and requeues them instead of marking them failed; this doesn't use up one of the job's attempts. It waits up to `WORKER_SHUTDOWN_GRACE_SEC` (default 60) before forcing them. The systemd units set `TimeoutStopSec=90` and the Docker worker gets `stop_grace_period: 90s` to allow for this.
- The worker runs `recover` once at startup, so jobs orphaned by a crash or reboot are requeued right away.
- The worker doesn't claim jobs while the queue is paused, even if some are still `pending`.

## [0.5.2] - 2026-11-04

### Reports
- The all-reports ZIP now includes the HTML version of every report alongside its PDF (`kitelon-report.html`/`.pdf`, `pentest-report.*`, `ssl-report.*`, `ssl-<host>-<port>.*`). Opt out with `--pdf-only` (bash), `--no-html` (kitelon-cli and `bin/kitelon_report_bundle.py`), or `?html=false` (API).
- If PDF rendering is unavailable (no `pdfkit`/`wkhtmltopdf`), the ZIP still exports with the HTML versions and a `MISSING-PDFS.txt` listing what couldn't be rendered, instead of failing.
- Web UI button renamed to **Reports (ZIP)**.

## [0.5.1] - 2026-11-03

### CI / Docker
- Fix `docker-publish` failing with "no space left on device" during the image build. `docker-publish` and `docker-weekly` now free ~25-30 GB of preinstalled runner toolchains (.NET, Android, GHC, CodeQL, ...) before building.
- `docker-publish`: add `workflow_dispatch` for manual runs. The image tag is the optional `version` input, else `v` + `VERSION`; tag pushes still use the tag name.
- Dockerfile: clear Go module/build caches, pip/apt caches and `/tmp` in the `install.sh` layer so they are not shipped in the image.

## [0.5.0] - 2026-11-03

### Reports
- All-reports PDF bundle: render the scan report, pentest workbook, SSL/TLS index, and each per-host SSL/TLS report to PDF and pack them into one ZIP. Available from every surface: **Reports PDF (ZIP)** button on the workspace page, `GET /api/v1/workspaces/<alias>/reports.zip`, `kitelon -w <alias> --reports-zip [--output PATH]` (bash), `workspace reports <alias> [-o OUT] [--force]` (kitelon-cli), and `bin/kitelon_report_bundle.py`. Reports that are unavailable (e.g. no SSL data) are skipped; a missing PDF toolchain returns 503.

### Scanning
- `full-audit` now runs an SSL/TLS (testssl + tlsx) check on every recon-discovered host with port 443 open, not just the apex target. Added a reusable `ssl_stack` pipeline step.

### Install / Docker
- Bump Go toolchain to 1.27.3 (pinned tarball SHA256 updated) for CVE-2026-111943, CVE-2026-78667, CVE-2026-78669, and CVE-2026-97031 in Go stdlib.

### CI
- `vet`: run the vet-action step only on push / pull_request. The action throws "Unsupported event type: workflow_dispatch" (manual docker-weekly runs failed) and does nothing on schedule.
- `docker-weekly`: build with `no-cache: true` (still writes the GHA cache). Every layer was restored from cache, so the weekly refresh never re-ran `apt-get full-upgrade` or `install.sh` and kept shipping stale packages (e.g. certifi 2026.7.22, GHSA-6q48-6c7w-9gw2), failing the Trivy scan.

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
- Upgrade pip `cryptography` to >=50.0.0 (and `pyOpenSSL` with it) after plugin requirements so Trivy no longer fails publish on CVE-2026-69247, CVE-2026-69249, and GHSA-537c-gmf6-5ccf.
- Fix stale `*.dist-info` prune regex so leftover pip METADATA dirs are actually removed.

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
