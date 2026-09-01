# Kitelon

Kitelon is a security automation platform for **authorized**
reconnaissance, vulnerability scanning, and reporting in lab and engagement
contexts. It orchestrates engine-integrated security tools through a CLI-first
workflow with workspace-based loot management.

## Why Kitelon

Kitelon is an **independent** open-source project (MIT). It is **not**
affiliated with, endorsed by, or derived from the [Sn1per](https://github.com/1N3/Sn1per)
product or its authors.

The public Sn1per **community edition** on GitHub is **updated infrequently**
and is **not the main development line**. Recent commits are largely
documentation and marketing; the **last GitHub release (v9.2) was in July
2023**. Ongoing work is centered on **Sn1per Professional**, a commercial
product. That is a poor fit for students, home labs, and teams who need
multi-tool scan automation to learn defensive security or to exercise
**systems they own or are authorized to test**, without buying a platform
license.

Kitelon targets that gap with a **new** stack: Python pipelines, a PostgreSQL
job queue, background workers, cron schedules, and a local Web UI. Scan modes
and workspace loot follow the same **orchestrator** pattern many operators
already know from tools in this category; the source here is Kitelon-authored,
not a Sn1per fork or rebrand.

> **Authorized use only.** Kitelon is for educational purposes and permitted
> security testing. Scan only systems you own or are explicitly authorized to
> assess. See [docs/LEGAL.md](docs/LEGAL.md) and [NOTICE.md](NOTICE.md).

## How it was built

I'm a **DevOps engineer**. I built Kitelon with **heavy assistance from AI
coding tools** (implementation, documentation, and Web UI). This is a **hobby
project**, not a day job or commercial product. My background is DevOps,
infrastructure, and tool orchestration, not front-end development; I used AI
help so a working local Web UI and docs could ship in spare time without
overstating the scope of the effort.

## Install

### Linux (Kali / Ubuntu / Debian / Parrot / Pop!_OS)

```bash
cd /path/to/kitelon
sudo bash install.sh
```

Install location: `/usr/share/kitelon`

CLI command: `kitelon`

Interactive console: `kitelon-cli` (see [docs/CLI.md](docs/CLI.md))

### Docker

Full stack (PostgreSQL + Web UI + job worker):

```bash
cp docker/env.example .env   # set POSTGRES_PASSWORD
docker compose build         # first build runs install.sh (~30+ min)
docker compose up -d
# → http://127.0.0.1:8080
```

Single container (CLI / one-off scan):

```bash
docker build -t kitelon:local .
docker run -it --rm --cap-add=NET_RAW --cap-add=NET_ADMIN kitelon:local help
docker compose run --rm --profile scan kitelon-scan -- -t example.com -w demo
```

Slim dev image (API/worker only, no offensive tool install):

```bash
docker build -f docker/Dockerfile.dev -t kitelon:dev .
```

See [docker/env.example](docker/env.example) for compose variables. Loot and logs persist in Docker volumes (`kitelon_loot`, `kitelon_logs`).

## Quick start

```bash
# Default scan
sudo kitelon -t example.com

# Stealth + OSINT + recon
sudo kitelon -t example.com -m stealth -o -re

# Workspace scan
sudo kitelon -t example.com -w myproject

# List workspaces
sudo kitelon --list
```

## Scan modes

| Mode | Description |
|------|-------------|
| `normal` | Default: DNS, port scan, service plugins, web scans |
| `stealth` | Lightweight, WAF/IPS-aware enumeration |
| `web` | Web app scan on ports 80 + 443 |
| `web-deep` | Deep HTTP/HTTPS scan (optional ZAP) |
| `web-http` / `web-https` | Web stack on a single port (set `-p`) |
| `discover` | CIDR walk; scan each live host |
| `recon` | Subdomain enumeration and light port scan |
| `osint` | WHOIS and OSINT collectors |
| `allports` | All TCP ports, then web on 80/443 |
| `ports-only` | Full port scan without follow-on modules |
| `ports-quick` | Light port scan only |
| `port` | Single-port scan (set `-p`) |
| `vuln` | Vulnerability templates on web ports |
| `batch-ports` / `batch-web` / `batch-webdeep` / `batch-vuln` | Same as above, from `-f` target file |
| `batch-ports-fast` | Fast multi-target port scan from file |
| `full-audit` | OSINT, recon, web-deep, and vuln modules |

Run `sudo kitelon --help` for the full command reference.

## Configuration

- Template: `examples/kitelon.conf` (reference only: document all options; not copied by install)
- Local override: `kitelon.conf` in the installer directory (gitignored; used by install if present)
- Installed config: `/usr/share/kitelon/kitelon.conf`
- Runtime config: `/root/.kitelon.conf` (symlinked from install dir on Linux)
- DB password: `/root/.kitelon_db.conf` (chmod 600)
- API keys: `/root/.kitelon_api_keys.conf`
- Presets: `conf/` directory

During install, if `kitelon.conf` exists in the installer directory it is used; otherwise the installer prompts for settings and creates one. See `examples/kitelon.conf` for a documented reference of all options. PostgreSQL credentials are written to `/root/.kitelon.conf` and `/root/.kitelon_db.conf` when provided.

## Loot and workspaces

Scan output is stored under `/usr/share/kitelon/loot/workspace/<alias>/`.

## Updates

Auto-updates from upstream are disabled by default. To update from a git remote
you configure:

```bash
sudo kitelon -u
```

## Engine

The scan engine includes:

- **httpx** for HTTP probing (set `HTTPX=1` in config)
- **gowitness** for screenshots (set `GOWITNESS=1`)
- **enum4linux-ng** and **smbmap** for SMB enumeration
- **nuclei v3** with templates under `/usr/share/kitelon/plugins/nuclei-templates/`
- **Resume scans** with `-rr` to skip steps that already produced loot

```bash
sudo kitelon -t example.com -w myscope -rr
```

Re-run `sudo bash install.sh force` after upgrading to pick up new tools. See [docs/TOOLS.md](docs/TOOLS.md) for upstream sources, versions, and CLI flags used by Kitelon.

## Data and reports

PostgreSQL (`kitelon` database) holds hosts, findings, jobs, schedules, and optional artifact blobs. Loot files stay on disk under `loot/workspace/<alias>/` during scans; the worker imports them when `LOOT_DB=1`.

- HTML workspace report at `kitelon-report.html`
- Subset PDF/HTML for selected hosts (Web UI checkboxes or `?hosts=` query params)
- CSV host table at `reports/host-table-report.csv`
- SSL/TLS via testssl.sh (`TESTSSL=1` or `--testssl`); reports in the Web UI
- Rebuild: `sudo kitelon -w <alias> --reimport`
- Active scan check: `sudo kitelon --is-running`; stop with `sudo kitelon --stop`

```bash
# Toggle in /root/.kitelon.conf
LOOT_DB="1"       # import loot into PostgreSQL
LOOT_REPORT="1"   # generate HTML + CSV reports
DB_ENABLED="1"    # PostgreSQL + schedules
LOOT_ARTIFACTS_DB="1"   # archive reports and loot files in PostgreSQL
LOOT_FS_MIRROR="1"      # also write artifacts to loot/ (set 0 for DB-only reports)
LOOT_FS_PRUNE="0"         # delete FS copies after DB archive (requires LOOT_FS_MIRROR=0)
```

### Workspace portability

Export or import a full workspace (hosts, findings, stats, archived artifacts):

```bash
sudo kitelon workspaces export myscope -o /tmp/myscope.zip
sudo kitelon --import-zip /tmp/myscope.zip --replace
sudo kitelon -w myscope --export
```

Web UI: **Export ZIP** on the workspace page; **Import workspace ZIP** on the home page.

### PostgreSQL setup

```bash
# 1. Create DB (once)
psql -U postgres -h 127.0.0.1 -c "CREATE DATABASE kitelon;"

# 2. Store password (never commit this file)
sudo cp /usr/share/kitelon/conf/kitelon_db.conf.example /root/.kitelon_db.conf
sudo chmod 600 /root/.kitelon_db.conf
# edit DB_PASSWORD=...

# 3. Migrate schema + start worker
sudo kitelon db test
sudo kitelon db migrate
sudo kitelon db migrate-artifacts
sudo systemctl enable --now kitelon-worker kitelon-worker-cron.timer
```

The default worker runs **two pools in one process**: a scan pool (one scan at a time) and a post-process pool (import + HTML/PDF reports, default 2 concurrent workers). Long scans no longer block report generation for other workspaces.

Optional split systemd units (disable `kitelon-worker` first):

```bash
sudo systemctl disable --now kitelon-worker
sudo systemctl enable --now kitelon-worker-scan kitelon-worker-post
```

Tune post-process concurrency via `WORKER_POST_CONCURRENCY` in `kitelon-worker.service` or `kitelon-worker-post.service`.

```bash
sudo kitelon db migrate-loot
```

### Web UI + job queue

```bash
sudo kitelon --web
# → http://127.0.0.1:8080

sudo kitelon jobs list
sudo kitelon jobs enqueue -t example.com -w myscope -m normal

# Recurring scan (requires -t, -w, DB_ENABLED=1)
sudo kitelon -t example.com -w myscope -s "0 2 * * *"
```

API key: set `WEB_API_KEY` in `/root/.kitelon_api_keys.conf` (sent as `X-API-Key`). If the file is empty, `kitelon --web` generates a key on first start.

**REST CRUD** (all JSON API routes require `X-API-Key`):

| Resource | Create | Read | Update | Delete |
|----------|--------|------|--------|--------|
| Workspaces | `POST /api/v1/workspaces` `{alias}` | `GET /api/v1/workspaces`, `GET .../{alias}` | `PATCH .../{alias}` `{alias}` | `DELETE .../{alias}?delete_loot=true` |
| Jobs | `POST /api/v1/jobs` | `GET /api/v1/jobs`, `GET .../{id}` | `PATCH .../{id}` pending only | `DELETE .../{id}?kill=true` if running |

CLI equivalents: `kitelon workspaces list|show|create|update|delete` and `kitelon jobs list|show|create|update|delete|retry`.

**Schedules:** `GET/POST /api/v1/schedules`, `GET/PATCH/DELETE /api/v1/schedules/{id}`: Web UI at `/schedules.html`.

**Scanner imports:** `POST /api/v1/workspaces/{alias}/import/nessus` and `.../import/burp` (multipart file upload).

**Scan config:** `GET /api/v1/scan-config`: pass `options` when creating jobs or schedules (`resume`, `osint`, `recon`, `fullportscan`, `port`).

**Connection errors:** if migrate fails with `password authentication failed`, the password in `/root/.kitelon_db.conf` does not match the PostgreSQL user (default `DB_USER=postgres` in `/root/.kitelon.conf`). Fix credentials, then run `sudo kitelon db test` before migrate.

Optional PDF export (installed by `install.sh` as `pdfkit` + `wkhtmltopdf`):

```bash
python3 /usr/share/kitelon/bin/report.py --loot-dir /usr/share/kitelon/loot/workspace/myscope
```

## Hooks

Optional post-scan hook: `/usr/share/kitelon/hooks/post-loot.sh`

## License

MIT: see [LICENSE.md](LICENSE.md). Use for **authorized security testing and education only**: [docs/LEGAL.md](docs/LEGAL.md).
