"""Context-sensitive help for kitelon-cli commands (`<cmd> … help`)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from kitelon_engine.cli.shell import KitelonShell

Handler = Callable[["KitelonShell", list[str]], None]

CONTEXT_HELP_COMMANDS = frozenset({"workspace", "jobs", "schedule", "scan", "db", "use"})


def _out(shell: KitelonShell, text: str) -> None:
    shell.poutput(text.rstrip())


def _workspace(shell: KitelonShell, parts: list[str]) -> None:
    if not parts:
        _out(
            shell,
            """
workspace: manage scan workspaces

Subcommands:
  list                         List all workspaces
  show <ALIAS> [--json]        Show workspace details and stats
  show <ALIAS> ssl [HOST]      List SSL/TLS scans or show one host (--open for browser)
  show ssl [HOST]              Same, using session workspace (after `use`)
  create <ALIAS>               Create (or refresh) a workspace
  update <ALIAS> --rename NEW  Rename a workspace
  rename-host <ALIAS> <HOST> <NEW_NAME>
                               Rename a host inside a workspace
  delete <ALIAS> [--delete-loot]
                               Delete workspace row (optional loot removal)

Examples:
  workspace list
  workspace show nmap-test
  workspace create demo
  workspace update demo --rename demo-prod
  workspace delete demo --delete-loot

Tip: append help after any subcommand for detailed usage, e.g. workspace show help
""",
        )
        return
    sub = parts[0]
    if sub == "list":
        _out(
            shell,
            """
workspace list: list workspaces

Usage:
  workspace list [--json]

Examples:
  workspace list
  workspace list --json
""",
        )
    elif sub == "show":
        if len(parts) >= 2 and parts[1] == "ssl":
            _out(
                shell,
                """
workspace show ssl: SSL/TLS scans in session workspace

Usage:
  workspace show ssl [HOST] [-p PORT] [--open] [--json]

Requires: use <WORKSPACE> (or use workspace show <ALIAS> ssl …)

Examples:
  use nmap-test
  workspace show ssl
  workspace show ssl scanme.nmap.org
  workspace show ssl scanme.nmap.org --open
""",
            )
        elif len(parts) >= 3 and parts[2] == "ssl":
            _out(
                shell,
                """
workspace show <ALIAS> ssl: SSL/TLS scans in a workspace

Usage:
  workspace show <ALIAS> ssl [HOST] [-p PORT] [--open] [--json]

Examples:
  workspace show nmap-test ssl
  workspace show nmap-test ssl scanme.nmap.org
  workspace show nmap-test ssl scanme.nmap.org -p 443 --open
""",
            )
        else:
            _out(
                shell,
                """
workspace show: show one workspace

Usage:
  workspace show <ALIAS> [--json]
  workspace show <ALIAS> ssl [HOST] [-p PORT] [--open]

Examples:
  workspace show nmap-test
  workspace show nmap-test ssl
  workspace show nmap-test ssl scanme.nmap.org --open
""",
            )
    elif sub == "create":
        _out(
            shell,
            """
workspace create: create a workspace

Usage:
  workspace create <ALIAS>

Creates loot directories under loot/workspace/<ALIAS> and registers the workspace in PostgreSQL.

Examples:
  workspace create client-a
  workspace create scanme-nmap-org
""",
        )
    elif sub == "update":
        _out(
            shell,
            """
workspace update: rename a workspace

Usage:
  workspace update <ALIAS> --rename <NEW_ALIAS>

Examples:
  workspace update demo --rename demo-prod
""",
        )
    elif sub == "rename-host":
        _out(
            shell,
            """
workspace rename-host: rename a host in a workspace

Usage:
  workspace rename-host <ALIAS> <HOSTNAME> <NEW_NAME>

Examples:
  workspace rename-host nmap-test 10.0.0.5 web-server-01
""",
        )
    elif sub == "delete":
        _out(
            shell,
            """
workspace delete: remove a workspace

Usage:
  workspace delete <ALIAS> [--delete-loot]

Examples:
  workspace delete demo
  workspace delete demo --delete-loot
""",
        )
    else:
        _out(shell, f"Unknown workspace subcommand: {sub}\nTry: workspace help")


def _jobs(shell: KitelonShell, parts: list[str]) -> None:
    if not parts:
        _out(
            shell,
            """
jobs: list, create, and manage background jobs

Subcommands:
  list [--status STATUS] [-w WORKSPACE] [--limit N]
  show <ID>
  create --type TYPE -w WORKSPACE [-t TARGET] [-m MODE]
  update <ID> [--priority N] [-t TARGET] [-m MODE] ...
  delete <ID> [--kill]
  retry <ID>
  wait <ID> | wait --last

Examples:
  jobs list
  jobs list --status running
  jobs show 42
  jobs create --type scan -w demo -t example.com -m normal
  jobs wait --last

Tip: jobs show help
""",
        )
        return
    sub = parts[0]
    if sub == "list":
        _out(
            shell,
            """
jobs list: list queued and completed jobs

Usage:
  jobs list [--status STATUS] [-w WORKSPACE] [--limit N]

Status values: pending, running, completed, failed, cancelled

Examples:
  jobs list
  jobs list --status failed -w nmap-test
  jobs list --limit 20
""",
        )
    elif sub == "show":
        _out(
            shell,
            """
jobs show: show job details

Usage:
  jobs show <ID>

Examples:
  jobs show 14
  jobs show 42
""",
        )
    elif sub == "create":
        _out(
            shell,
            """
jobs create: enqueue a job

Usage:
  jobs create --type scan|reimport|loot_process|report \\
    [-w WORKSPACE] [-t TARGET] [-m MODE] [--priority N] [--args JSON]

Examples:
  jobs create --type scan -w demo -t scanme.nmap.org -m normal
  jobs create --type loot_process -w demo
""",
        )
    elif sub == "wait":
        _out(
            shell,
            """
jobs wait: block until a job finishes

Usage:
  jobs wait <ID>
  jobs wait --last

--last waits on the most recent job enqueued in this session (after scan, etc.).

Examples:
  jobs wait 42
  scan -t example.com -w demo && jobs wait --last
""",
        )
    elif sub == "delete":
        _out(
            shell,
            """
jobs delete: cancel or remove a job

Usage:
  jobs delete <ID> [--kill]

Examples:
  jobs delete 42
  jobs delete 42 --kill
""",
        )
    elif sub == "retry":
        _out(
            shell,
            """
jobs retry: re-queue a failed or completed job

Usage:
  jobs retry <ID>

Examples:
  jobs retry 14
""",
        )
    elif sub == "update":
        _out(
            shell,
            """
jobs update: change a pending job

Usage:
  jobs update <ID> [--priority N] [-t TARGET] [-m MODE] [--type TYPE] [-w WORKSPACE]

Examples:
  jobs update 42 --priority 50
""",
        )
    else:
        _out(shell, f"Unknown jobs subcommand: {sub}\nTry: jobs help")


def _schedule(shell: KitelonShell, parts: list[str]) -> None:
    if not parts:
        _out(
            shell,
            """
schedule: recurring scan schedules (cron)

Subcommands:
  list [-w WORKSPACE]
  show <ID>
  create -w WORKSPACE --cron CRON -t TARGET [-m MODE] [scan options]
  delete <ID>

Examples:
  schedule list
  schedule create -w demo --cron "0 2 * * *" -t example.com -m normal

Tip: schedule create help
""",
        )
        return
    sub = parts[0]
    if sub == "list":
        _out(
            shell,
            """
schedule list: list cron schedules

Usage:
  schedule list [-w WORKSPACE]

Examples:
  schedule list
  schedule list -w nmap-test
""",
        )
    elif sub == "show":
        _out(
            shell,
            """
schedule show: show one schedule

Usage:
  schedule show <ID>

Examples:
  schedule show 3
""",
        )
    elif sub == "create":
        _out(
            shell,
            """
schedule create: add a recurring scan

Usage:
  schedule create -w WORKSPACE --cron CRON -t TARGET [-m MODE]
    [--osint] [--recon] [--fullportscan] [--testssl] [-p PORT]

Cron uses standard 5-field syntax (minute hour dom month dow).

Examples:
  schedule create -w demo --cron "0 2 * * *" -t example.com
  schedule create -w demo --cron "0 */6 * * *" -t scanme.nmap.org -m web
""",
        )
    elif sub == "delete":
        _out(
            shell,
            """
schedule delete: remove a schedule

Usage:
  schedule delete <ID>

Examples:
  schedule delete 3
""",
        )
    else:
        _out(shell, f"Unknown schedule subcommand: {sub}\nTry: schedule help")


def _scan(shell: KitelonShell, parts: list[str]) -> None:
    from kitelon_scan_config import SCAN_MODES, SCAN_OPTIONS

    if not parts:
        _out(shell, "scan: queue or run a target scan\n")
        shell.help_scan()
        _out(
            shell,
            """
Usage:
  scan -t TARGET [-w WORKSPACE] [-m MODE] [options] [--sync] [--wait]

Workspace is required: pass -w or `use <alias>` first.

Examples:
  scan -t scanme.nmap.org -w scanme -m normal
  use demo && scan -t example.com -m web --osint
  scan -t example.com -w demo --sync
  scan -t example.com -w demo && jobs wait --last
""",
        )
        return
    _out(shell, "For scan flags, use: scan help\nOr: help scan")


def _db(shell: KitelonShell, parts: list[str]) -> None:
    if not parts:
        _out(
            shell,
            """
db: database maintenance

Subcommands:
  migrate            Apply SQL migrations
  test               Test PostgreSQL connectivity
  prune-workspaces   Remove invalid workspace rows; sync from disk
  fix-loot-layout    Repair loot/workspace directory layout

Examples:
  db test
  db migrate
  db prune-workspaces

Tip: db migrate help
""",
        )
        return
    sub = parts[0]
    if sub == "migrate":
        _out(
            shell,
            """
db migrate: apply PostgreSQL migrations

Usage:
  db migrate

Run after upgrading Kitelon or pulling new sql/migrations/*.sql files.
""",
        )
    elif sub == "test":
        _out(
            shell,
            """
db test: verify database connection

Usage:
  db test
""",
        )
    elif sub == "prune-workspaces":
        _out(
            shell,
            """
db prune-workspaces: clean workspace table vs loot on disk

Usage:
  db prune-workspaces

Removes bogus workspace rows and re-registers workspaces found under loot/workspace/.
""",
        )
    elif sub == "fix-loot-layout":
        _out(
            shell,
            """
db fix-loot-layout: repair loot directory layout

Usage:
  db fix-loot-layout

Ensures loot/workspace is canonical and loot/workspaces symlinks correctly.
""",
        )
    else:
        _out(shell, f"Unknown db subcommand: {sub}\nTry: db help")


def _use(shell: KitelonShell, _parts: list[str]) -> None:
    _out(
        shell,
        """
use: set default workspace for this session

Usage:
  use <WORKSPACE>

The session workspace is used when -w / --workspace is omitted on scan, jobs, and schedule.

Examples:
  use nmap-test
  use demo && scan -t example.com

See current context: context
""",
    )


_HANDLERS: dict[str, Handler] = {
    "workspace": _workspace,
    "jobs": _jobs,
    "schedule": _schedule,
    "scan": _scan,
    "db": _db,
    "use": _use,
}


def show_context_help(shell: KitelonShell, command: str, parts: list[str]) -> None:
    handler = _HANDLERS.get(command)
    if handler:
        handler(shell, parts)
