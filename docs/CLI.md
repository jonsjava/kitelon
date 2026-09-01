# kitelon-cli

Interactive console for workspaces, jobs, schedules, and scans. Uses the same PostgreSQL queue as the Web UI and `kitelon` bash driver.

## Launch

```bash
sudo kitelon-cli
sudo kitelon-cli -c 'db test'
sudo kitelon-cli --no-intro -c 'jobs list --limit 5'
```

Chain with `;` (always continue) or `&&` (continue on success):

```text
kitelon> workspace create demo && use demo && scan -t scanme.nmap.org -m normal
kitelon[demo]> scan -t example.com && jobs wait --last
```

## Session

```text
use <workspace>          # default -w for scan/jobs/schedule
context                  # show workspace + last job id
```

## Commands (summary)

| Command | Purpose |
|---------|---------|
| `scan -t TARGET [-w WS] [-m MODE] [opts] [--sync] [--wait]` | Queue or run scan (`--sync` = foreground) |
| `workspace list\|show\|create\|update\|delete\|rename-host` | Workspace CRUD |
| `workspace show ssl [HOST] [--open]` | testssl summaries / open HTML report |
| `workspace show services\|tech\|urls\|scan-runs` | Enriched DB views after loot import |
| `jobs list\|show\|create\|update\|delete\|retry\|wait` | Job queue |
| `schedule list\|show\|create\|delete` | Cron schedules (5-field syntax) |
| `db migrate\|test\|import\|prune-workspaces\|fix-loot-layout` | DB maintenance |

Scan options: `--resume`, `--osint`, `--recon`, `--fullportscan`, `--testssl`, `-p PORT`. Run `help scan` in the REPL for modes.

Append `help` to any command for usage, e.g. `workspace show help`, `jobs wait help`.

## Logging

Rotating logs under `LOG_DIR` (default `/var/log/kitelon`): `cli.log`, `api.log`, `worker.log`, `engine.log`, `core.log`. Set `LOG_*` in `kitelon.conf`.

History file: `~/.local/share/kitelon/cli_history` (`KITELON_CLI_HISTORY` to override).

## Requirements

- Run as **root** (same as `kitelon`)
- PostgreSQL + migrations applied
- `kitelon_worker` running for queued scans (not needed for `--sync`)

Wrapper: `/usr/local/bin/kitelon-cli` (installed by `install.sh`; do not symlink the `.py` directly).

If the wrapper breaks after a bad overwrite, rerun `sudo bash install.sh force` from the repo.
