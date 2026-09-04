"""cmd2 shell for kitelon-cli."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

import cmd2
from cmd2 import Cmd, Cmd2ArgumentParser, Completions, with_argparser, with_category

# Keep ? -> help; omit cmd2 escape hatches (! shell, @ run_script, etc.).
_KITELON_SHORTCUTS = {"?": "help"}

# cmd2 built-ins that are not part of the Kitelon CLI surface.
_DISABLED_CMD2_COMMANDS = (
    "shell",
    "run_script",
    "_relative_run_script",
    "run_pyscript",
    "alias",
    "macro",
    "edit",
    "set",
    "shortcuts",
    "history",
)
_DISABLED_CMD2_MESSAGE = "The {name} command is disabled in kitelon-cli."

from kitelon_db import (
    ALL_JOB_TYPES,
    POST_JOB_TYPES,
    create_workspace,
    delete_job,
    delete_schedule,
    delete_workspace,
    enqueue_job,
    get_connection,
    get_job,
    get_schedule,
    get_workspace_by_alias,
    list_discovered_urls,
    list_jobs,
    list_scan_runs,
    list_schedules,
    list_services,
    list_technologies,
    list_workspaces,
    retry_job,
    update_job,
    update_workspace,
    rename_host,
    workspace_stats,
)
from kitelon_engine.cli.chain import has_chain, tokenize_chain
from kitelon_engine.cli.completers import (
    CRON_EXAMPLES,
    JOB_STATUSES,
    mode_choices_provider,
    port_choices_provider,
    preset_choices_provider,
    recent_job_ids,
    recent_schedule_ids,
    target_choices_provider,
    workspace_aliases,
    workspace_choices_provider,
)
from kitelon_engine.cli.services import (
    CliError,
    LOOT_ROOT,
    build_scan_options,
    create_scan_schedule,
    enqueue_scan,
    ensure_workspace_id,
    format_ssl_findings_summary,
    get_workspace_ssl_scan,
    list_workspace_ssl_scans,
    resolve_workspace,
    run_db_command,
    run_db_import,
    run_sync_scan,
    wait_for_job,
)
from kitelon_engine.cli.help_text import CONTEXT_HELP_COMMANDS, show_context_help
from kitelon_engine.cli.session import SessionContext
from kitelon_log import get_logger
from kitelon_scan_config import SCAN_MODES, SCAN_OPTIONS, VALID_MODE_IDS


def _package_version() -> str:
    here = Path(__file__).resolve()
    for candidate in (here.parents[3] / "VERSION", Path("/usr/share/kitelon/VERSION")):
        try:
            text = candidate.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if text:
            return text
    return "0.0.0"


VERSION = _package_version()


def _cli_history_file() -> str:
    override = os.environ.get("KITELON_CLI_HISTORY")
    if override:
        return str(Path(override).expanduser())
    return str(Path.home() / ".local" / "share" / "kitelon" / "cli_history")


def _add_scan_option_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-rr", dest="resume", action="store_true", help="Skip completed pipeline steps")
    parser.add_argument(
        "-o",
        dest="osint",
        action="store_true",
        help="OSINT: whois, theHarvester; Shodan/Censys when API keys set",
    )
    parser.add_argument(
        "-re",
        dest="recon",
        action="store_true",
        help="Recon: subfinder, dnsx, dnsrecon, gau",
    )
    parser.add_argument("-fp", dest="fullportscan", action="store_true", help="Scan all TCP ports")
    parser.add_argument("-ts", dest="testssl", action="store_true", help="Run testssl on HTTPS targets")
    parser.add_argument("-fu", dest="ffuf", action="store_true", help="Run ffuf path discovery")
    parser.add_argument(
        "-pr",
        dest="preset",
        help="Preset from conf/presets/ (osint-conservative, osint-deep, …)",
        choices_provider=preset_choices_provider,
    )
    parser.add_argument("-p", dest="port", type=int, help="Limit to a specific port", choices_provider=port_choices_provider)


def _workspace_arg(parser: argparse.ArgumentParser, *, with_completion: bool = False) -> None:
    kwargs: dict = {"help": "Workspace alias (defaults to session workspace)"}
    if with_completion:
        kwargs["choices_provider"] = workspace_choices_provider
    parser.add_argument("-w", "--workspace", **kwargs)


class KitelonShell(Cmd):
    intro = (
        "Kitelon interactive CLI: chain commands with ; or &&\n"
        "Examples:\n"
        "  workspace create demo && use demo && scan -t scanme.nmap.org\n"
        "  use demo && scan -t example.com -m normal -o -re -pr osint-deep\n"
        "  scan -t a.example.com ; scan -t b.example.com\n"
        "Type help or help <command> for details. Append help to any command for usage, e.g. workspace show help.\n"
        "Ctrl+C to exit."
    )
    prompt = "kitelon> "

    def __init__(self, *, show_intro: bool = True) -> None:
        history_path = _cli_history_file()
        Path(history_path).parent.mkdir(parents=True, exist_ok=True)
        super().__init__(
            allow_cli_args=False,
            include_py=False,
            include_ipy=False,
            intro=self.intro if show_intro else "",
            shortcuts=_KITELON_SHORTCUTS,
            persistent_history_file=history_path,
            persistent_history_length=int(os.environ.get("KITELON_CLI_HISTORY_LENGTH", "2000")),
        )
        for command in _DISABLED_CMD2_COMMANDS:
            self.disable_command(command, _DISABLED_CMD2_MESSAGE.format(name=command))
        if "kl_noop" not in self.hidden_commands:
            self.hidden_commands.append("kl_noop")
        self.session = SessionContext()
        self._show_intro = show_intro
        self.last_result: Any = True
        self._cli_logger = get_logger("cli")
        self.register_postcmd_hook(self._refresh_prompt_hook)
        self.register_postcmd_hook(self._log_command_hook)
        self.register_postparsing_hook(self._intercept_context_help)
        self._refresh_prompt()

    def _refresh_prompt(self) -> None:
        ws = self.session.workspace
        self.prompt = f"kitelon[{ws}]> " if ws else "kitelon> "

    def _refresh_prompt_hook(self, data: cmd2.plugin.PostcommandData) -> cmd2.plugin.PostcommandData:
        self._refresh_prompt()
        return data

    def _log_command_hook(self, data: cmd2.plugin.PostcommandData) -> cmd2.plugin.PostcommandData:
        stmt = data.statement
        raw = (stmt.raw or "").strip()
        if raw and stmt.command not in ("_eof",):
            ws = self.session.workspace or "-"
            ok = self.last_result is not False
            self._cli_logger.info(
                "command workspace=%s ok=%s line=%r",
                ws,
                ok,
                raw,
            )
        return data

    def _intercept_context_help(self, data: cmd2.plugin.PostparsingData) -> cmd2.plugin.PostparsingData:
        stmt = data.statement
        if stmt.command not in CONTEXT_HELP_COMMANDS:
            return data
        parts = (stmt.args or "").strip().split()
        if not parts or parts[-1] != "help":
            return data
        show_context_help(self, stmt.command, parts[:-1])
        self.last_result = True
        # Skip the original command without stopping the REPL.
        data.stop = False
        data.statement = self.statement_parser.parse("kl_noop")
        return data

    def do_kl_noop(self, _arg: cmd2.Statement) -> bool:
        """Internal no-op used after context-sensitive help."""
        return False

    def _success(self, message: str | None = None) -> bool:
        if message:
            self.poutput(message)
        self.last_result = True
        return False

    def _failure(self, message: str) -> bool:
        self.perror(message)
        self.last_result = False
        return False

    def _handle_error(self, exc: Exception) -> bool:
        if isinstance(exc, CliError):
            return self._failure(str(exc))
        if isinstance(exc, SystemExit):
            return self._failure(str(exc))
        if isinstance(exc, ValueError):
            return self._failure(str(exc))
        raise exc

    def _resolve_ws(self, alias: str | None, *, required: bool = False) -> str | None:
        resolved = alias or self.session.workspace
        return resolve_workspace(resolved, required=required)

    def preloop(self) -> None:
        if not self._show_intro:
            self.intro = ""
        self._cli_logger.info("session started pid=%s history=%s", os.getpid(), _cli_history_file())

    def postloop(self) -> None:
        self._cli_logger.info("session ended")

    def _cmdloop(self) -> None:
        """Exit the REPL on Ctrl-C at the prompt (cmd2 default is to continue)."""
        try:
            stop = self.runcmds_plus_hooks(self._startup_commands)
            self._startup_commands.clear()

            while not stop:
                try:
                    line = self._read_command_line(self.prompt)
                except KeyboardInterrupt:
                    return
                except EOFError:
                    line = "_eof"

                try:
                    stop = self.onecmd_plus_hooks(line, raise_keyboard_interrupt=True)
                except KeyboardInterrupt:
                    return
        finally:
            with self.sigint_protection:
                if self._alert_thread is not None:
                    with self._alert_condition:
                        self._alert_shutdown = True
                        self._alert_condition.notify_all()
                    self._alert_thread.join(timeout=1.0)
                    self._alert_thread = None

    def onecmd_plus_hooks(self, line: str, **kwargs) -> bool:
        if has_chain(line):
            return self._run_chain(line, **kwargs)
        kwargs.setdefault("raise_keyboard_interrupt", True)
        stop = super().onecmd_plus_hooks(line, **kwargs)
        if self.last_result is None:
            self.last_result = True
        return stop

    def _run_chain(self, line: str, **kwargs) -> bool:
        tokens = tokenize_chain(line)
        last_ok = True
        i = 0
        add_history = kwargs.get("add_to_history", True)
        kwargs.setdefault("raise_keyboard_interrupt", True)
        while i < len(tokens):
            tok = tokens[i]
            if tok in (";", "&&"):
                i += 1
                continue
            if i > 0 and tokens[i - 1] == "&&" and not last_ok:
                break
            try:
                stop = super().onecmd_plus_hooks(
                    tok,
                    add_to_history=add_history and i == 0,
                    **{k: v for k, v in kwargs.items() if k != "add_to_history"},
                )
            except KeyboardInterrupt:
                return True
            last_ok = self.last_result is not False
            if stop:
                return True
            i += 1
            if i < len(tokens) and tokens[i] in (";", "&&"):
                i += 1
        return False

    # --- context ---

    @with_category("Session")
    def do_use(self, arg: cmd2.Statement) -> bool:
        """Set the default workspace for this session."""
        alias = (arg or "").strip()
        if not alias:
            return self._failure("usage: use <workspace>")
        try:
            resolve_workspace(alias, required=True)
        except CliError as exc:
            return self._failure(str(exc))
        self.session.workspace = alias
        self.session.clear_cache()
        self._refresh_prompt()
        return self._success(f"Using workspace {alias}")

    @with_category("Session")
    def do_context(self, _arg: cmd2.Statement) -> bool:
        """Show session workspace and last job id."""
        ws = self.session.workspace or "-"
        job = self.session.last_job_id if self.session.last_job_id is not None else "-"
        self.poutput(f"workspace: {ws}")
        self.poutput(f"last_job:  {job}")
        return self._success()

    # --- scan ---

    scan_parser = Cmd2ArgumentParser()
    scan_parser.add_argument(
        "-t",
        dest="target",
        required=True,
        help="Target host, domain, or CIDR",
        choices_provider=target_choices_provider,
    )
    _workspace_arg(scan_parser, with_completion=True)
    scan_parser.add_argument(
        "-m",
        dest="mode",
        default="normal",
        help="Scan mode (default: normal)",
        choices_provider=mode_choices_provider,
    )
    _add_scan_option_flags(scan_parser)
    scan_parser.add_argument("--sync", action="store_true", help="Run scan in foreground and import loot")
    scan_parser.add_argument("--wait", action="store_true", help="Wait for queued job to finish")
    scan_parser.add_argument("--priority", type=int, default=100)
    _mode_help = "\n".join(f"  {m['id']:14} {m['description']}" for m in SCAN_MODES)
    _opt_help = "\n".join(
        f"  {o['id']:14} {o.get('flag') or '':8} {o['description']}" for o in SCAN_OPTIONS
    )
    scan_parser.epilog = (
        f"Modes:\n{_mode_help}\n\nOptions:\n{_opt_help}\n\n"
        "Default: enqueue job. --sync: foreground scan + loot import. --wait: block on queued job."
    )

    @with_argparser(scan_parser)
    @with_category("Scanning")
    def do_scan(self, args: argparse.Namespace) -> bool:
        """Queue or run a scan against a target."""
        try:
            workspace = self._resolve_ws(args.workspace)
            options = build_scan_options(args)
            if not workspace:
                raise CliError("workspace required (use -w or `use <alias>`)")
            if args.sync:
                code = run_sync_scan(
                    target=args.target,
                    workspace=workspace,
                    mode=args.mode,
                    options=options,
                )
                if code != 0:
                    return self._failure(f"scan failed (exit {code})")
                return self._success(f"Scan completed for {args.target}")
            job_id = enqueue_scan(
                target=args.target,
                workspace=workspace,
                mode=args.mode,
                options=options,
                priority=args.priority,
            )
            self.session.last_job_id = job_id
            self.session.clear_cache()
            msg = f"Enqueued job #{job_id}"
            if args.wait:
                job = wait_for_job(job_id)
                if job["status"] != "completed":
                    err = job.get("error_message") or job["status"]
                    return self._failure(f"job #{job_id} {job['status']}: {err}")
                return self._success(f"Job #{job_id} completed")
            return self._success(msg)
        except CliError as exc:
            return self._failure(str(exc))

    # --- workspace ---

    workspace_parser = Cmd2ArgumentParser()
    ws_sub = workspace_parser.add_subparsers(dest="ws_cmd", required=True)

    p = ws_sub.add_parser("list")
    p.add_argument("--json", action="store_true")

    p = ws_sub.add_parser("show")
    p.add_argument(
        "tokens",
        nargs="+",
        help="<ALIAS> | ssl [HOST] | <ALIAS> ssl [HOST]",
    )
    p.add_argument("--json", action="store_true")
    p.add_argument("-p", "--port", default="443", help="TLS port for ssl HOST (default: 443)")
    p.add_argument("--open", action="store_true", help="Open HTML SSL report in browser")

    p = ws_sub.add_parser("create")
    p.add_argument("alias")

    p = ws_sub.add_parser("update")
    p.add_argument("alias")
    p.add_argument("--rename", required=True)

    p = ws_sub.add_parser("rename-host")
    p.add_argument("alias")
    p.add_argument("hostname")
    p.add_argument("new_name")

    p = ws_sub.add_parser("delete")
    p.add_argument("alias")
    p.add_argument("--delete-loot", action="store_true")

    @with_argparser(workspace_parser)
    @with_category("Workspaces")
    def do_workspace(self, args: argparse.Namespace) -> bool:
        """Manage scan workspaces."""
        try:
            if args.ws_cmd == "list":
                with get_connection() as conn:
                    rows = list_workspaces(conn)
                if args.json:
                    self.poutput(json.dumps(rows, indent=2, default=str))
                    return self._success()
                for ws in rows:
                    stats = ws.get("stats") or {}
                    self.poutput(
                        f"{ws['alias']:20} hosts={stats.get('hosts_total', 0):4} "
                        f"findings={stats.get('vulnerabilities_total', 0):4} "
                        f"{ws.get('loot_path') or ''}"
                    )
                return self._success()

            if args.ws_cmd == "show":
                return self._workspace_show(args)

            if args.ws_cmd == "create":
                ws_id, created = create_workspace(LOOT_ROOT, args.alias)
                self.session.clear_cache()
                verb = "Created" if created else "Updated"
                return self._success(f"{verb} workspace {args.alias} (id={ws_id})")

            if args.ws_cmd == "update":
                with get_connection() as conn:
                    ws = update_workspace(conn, args.alias, new_alias=args.rename, loot_root=LOOT_ROOT)
                self.session.clear_cache()
                if self.session.workspace == args.alias:
                    self.session.workspace = ws["alias"]
                self._refresh_prompt()
                return self._success(f"Renamed workspace {args.alias} -> {ws['alias']}")

            if args.ws_cmd == "rename-host":
                with get_connection() as conn:
                    ws = get_workspace_by_alias(conn, args.alias)
                    if not ws:
                        raise CliError(f"workspace not found: {args.alias}")
                    row = rename_host(conn, int(ws["id"]), args.hostname, args.new_name)
                return self._success(f"Renamed host {args.hostname} -> {row['hostname']} in {args.alias}")

            if args.ws_cmd == "delete":
                with get_connection() as conn:
                    ws = delete_workspace(conn, args.alias, delete_loot=args.delete_loot)
                self.session.clear_cache()
                if self.session.workspace == ws["alias"]:
                    self.session.workspace = None
                self._refresh_prompt()
                msg = f"Deleted workspace {ws['alias']}"
                if args.delete_loot:
                    msg += " (loot removed)"
                return self._success(msg)
        except CliError as exc:
            return self._failure(str(exc))
        except ValueError as exc:
            return self._failure(str(exc))
        return self._failure("unknown workspace command")

    def _parse_workspace_show_tokens(self, tokens: list[str]) -> tuple[str, str, str | None]:
        """Return (mode, alias, arg) where mode is info|ssl_*|services|tech|urls|scan_runs."""
        detail_cmds = {"ssl", "services", "tech", "urls", "scan-runs"}
        if not tokens:
            raise CliError(
                "usage: workspace show <ALIAS> | workspace show <ALIAS> "
                "ssl|services|tech|urls|scan-runs [HOST]"
            )
        if tokens[0] in detail_cmds:
            alias = self._resolve_ws(None, required=True)
            cmd = tokens[0]
            if cmd == "ssl":
                if len(tokens) == 1:
                    return "ssl_list", alias, None
                return "ssl_show", alias, tokens[1]
            if len(tokens) == 1:
                return cmd.replace("-", "_"), alias, None
            return cmd.replace("-", "_"), alias, tokens[1]
        alias = tokens[0]
        self._resolve_ws(alias, required=True)
        if len(tokens) == 1:
            return "info", alias, None
        detail = tokens[1]
        if detail not in detail_cmds:
            raise CliError(
                "usage: workspace show <ALIAS> | workspace show <ALIAS> "
                "ssl|services|tech|urls|scan-runs [HOST]"
            )
        if detail == "ssl":
            if len(tokens) == 2:
                return "ssl_list", alias, None
            return "ssl_show", alias, tokens[2]
        if len(tokens) == 2:
            return detail.replace("-", "_"), alias, None
        return detail.replace("-", "_"), alias, tokens[2]

    def _workspace_show(self, args: argparse.Namespace) -> bool:
        mode, alias, hostname = self._parse_workspace_show_tokens(list(args.tokens))
        if mode in ("services", "tech", "urls", "scan_runs"):
            with get_connection() as conn:
                ws = get_workspace_by_alias(conn, alias)
                if not ws:
                    raise CliError(f"workspace not found: {alias}")
                ws_id = int(ws["id"])
                host_filter = hostname
                if mode == "services":
                    rows = list_services(conn, ws_id, hostname=host_filter)
                elif mode == "tech":
                    rows = list_technologies(conn, ws_id, hostname=host_filter)
                elif mode == "urls":
                    rows = list_discovered_urls(conn, ws_id, hostname=host_filter)
                else:
                    rows = list_scan_runs(conn, ws_id)
            if args.json:
                self.poutput(json.dumps(rows, indent=2, default=str))
                return self._success()
            if not rows:
                self.poutput(f"No {mode.replace('_', ' ')} data for workspace {alias}.")
                return self._success()
            for row in rows:
                self.poutput(" ".join(f"{k}={v}" for k, v in dict(row).items() if v not in (None, "")))
            return self._success()

        if mode == "info":
            with get_connection() as conn:
                ws = get_workspace_by_alias(conn, alias)
                if not ws:
                    raise CliError(f"workspace not found: {alias}")
                data = dict(ws)
                data["stats"] = workspace_stats(conn, int(ws["id"]))
            if args.json:
                self.poutput(json.dumps(data, indent=2, default=str))
            else:
                for key, val in data.items():
                    if key == "stats":
                        self.poutput("stats:")
                        for sk, sv in val.items():
                            self.poutput(f"  {sk}: {sv}")
                    else:
                        self.poutput(f"{key}: {val}")
            return self._success()

        if mode == "ssl_list":
            rows = list_workspace_ssl_scans(alias)
            if args.json:
                self.poutput(json.dumps(rows, indent=2, default=str))
                return self._success()
            if not rows:
                self.poutput(f"No SSL/TLS scans in workspace {alias}.")
                self.poutput("Run: scan -t <TARGET> -w " + alias + " -ts")
                self.poutput("Or:  sudo kitelon -w " + alias + " -t <TARGET> --testssl-only")
                return self._success()
            self.poutput(f"SSL/TLS scans in {alias}:")
            self.poutput(f"{'HOST':24} {'PORT':6} {'GRADE':6} {'SCORE':6} REPORT")
            for row in rows:
                grade = row.get("grade") or "-"
                score = row.get("score") or "-"
                self.poutput(
                    f"{row['hostname']:24} {str(row['port']):6} {grade:6} {str(score):6} "
                    f"{row.get('report_path') or '-'}"
                )
            self.poutput("")
            self.poutput("Detail:  workspace show " + alias + " ssl <HOST>")
            self.poutput("Index:   loot/.../reports/ssl-report.html")
            return self._success()

        assert mode == "ssl_show" and hostname
        detail = get_workspace_ssl_scan(alias, hostname, str(args.port))
        if not detail:
            raise CliError(
                f"no SSL scan for {hostname}:{args.port} in workspace {alias}"
            )
        scan = detail["scan"]
        if args.json:
            self.poutput(json.dumps(detail, indent=2, default=str))
            return self._success()
        label = f"{detail['hostname']}:{detail['port']}"
        self.poutput(f"SSL/TLS: {label} (workspace {alias})")
        self.poutput(f"Grade:  {detail.get('grade') or '-'}")
        self.poutput(f"Score:  {detail.get('score') or '-'}")
        self.poutput("")
        self.poutput("Notable findings:")
        for line in format_ssl_findings_summary(scan):
            self.poutput(line)
        report = detail["report_path"]
        self.poutput("")
        self.poutput(f"Report: {report}")
        if args.open:
            import subprocess

            if report.is_file():
                subprocess.run(["xdg-open", str(report)], check=False)
            else:
                self.perror(f"report file not found: {report}")
        return self._success()

    # --- jobs ---

    jobs_parser = Cmd2ArgumentParser()
    job_sub = jobs_parser.add_subparsers(dest="job_cmd", required=True)

    p = job_sub.add_parser("list")
    p.add_argument("--status", choices=sorted(JOB_STATUSES))
    p.add_argument("-w", "--workspace", choices_provider=workspace_choices_provider)
    p.add_argument("--limit", type=int, default=50)

    p = job_sub.add_parser("show")
    p.add_argument("id", type=int)

    p = job_sub.add_parser("create")
    p.add_argument("--type", default="scan", choices=ALL_JOB_TYPES)
    p.add_argument("-w", "--workspace", choices_provider=workspace_choices_provider)
    p.add_argument("-t", "--target")
    p.add_argument("-m", dest="mode", default="normal", choices_provider=mode_choices_provider)
    p.add_argument("--priority", type=int, default=100)
    p.add_argument("--args", help="JSON object for job args")

    p = job_sub.add_parser("update")
    p.add_argument("id", type=int)
    p.add_argument("--priority", type=int)
    p.add_argument("-t", "--target")
    p.add_argument("-m", dest="mode", choices_provider=mode_choices_provider)
    p.add_argument("--type", choices=ALL_JOB_TYPES)
    p.add_argument("-w", "--workspace")
    p.add_argument("--scheduled-at")
    p.add_argument("--args")

    p = job_sub.add_parser("delete")
    p.add_argument("id", type=int)
    p.add_argument("--kill", action="store_true")

    p = job_sub.add_parser("retry")
    p.add_argument("id", type=int)

    p = job_sub.add_parser("wait")
    p.add_argument("id", type=int, nargs="?", help="Job id (or --last)")
    p.add_argument("--last", action="store_true", help="Wait for session last_job_id")

    @with_argparser(jobs_parser)
    @with_category("Jobs")
    def do_jobs(self, args: argparse.Namespace) -> bool:
        """List, create, and manage background jobs."""
        try:
            if args.job_cmd == "list":
                with get_connection() as conn:
                    ws_id = None
                    if args.workspace:
                        ws = self._resolve_ws(args.workspace, required=True)
                        row = get_workspace_by_alias(conn, ws)
                        ws_id = int(row["id"]) if row else None
                    rows = list_jobs(conn, status=args.status, workspace_id=ws_id, limit=args.limit)
                for j in rows:
                    ws = j.get("workspace_alias") or "-"
                    self.poutput(
                        f"{j['id']:4} {j['status']:10} {j['job_type']:12} {ws:15} "
                        f"{j.get('target') or '-':20} {j.get('mode') or '-'}"
                    )
                    if j["status"] == "failed" and j.get("error_message"):
                        self.poutput(f"      error: {j['error_message']}")
                return self._success()

            if args.job_cmd == "show":
                with get_connection() as conn:
                    j = get_job(conn, args.id)
                if not j:
                    raise CliError(f"job not found: {args.id}")
                for label, key in (
                    ("id", "id"),
                    ("status", "status"),
                    ("type", "job_type"),
                    ("workspace", "workspace_alias"),
                    ("target", "target"),
                    ("mode", "mode"),
                    ("priority", "priority"),
                    ("exit_code", "exit_code"),
                    ("created_by", "created_by"),
                    ("scheduled_at", "scheduled_at"),
                    ("started_at", "started_at"),
                    ("finished_at", "finished_at"),
                    ("error", "error_message"),
                ):
                    self.poutput(f"{label:12} {j.get(key) or '-'}")
                return self._success()

            if args.job_cmd == "create":
                if args.type == "scan" and not args.target:
                    raise CliError("target required for scan jobs")
                workspace = args.workspace or self.session.workspace
                if args.type == "scan" and not workspace:
                    raise CliError("workspace required for scan jobs (use -w or `use`)")
                if args.type in POST_JOB_TYPES and not workspace:
                    raise CliError(f"workspace required for {args.type} jobs")
                with get_connection() as conn:
                    ws_id = None
                    if workspace:
                        ws_id = ensure_workspace_id(conn, workspace)
                    job_id = enqueue_job(
                        conn,
                        job_type=args.type,
                        workspace_id=ws_id,
                        target=args.target,
                        mode=args.mode,
                        args=json.loads(args.args) if args.args else None,
                        priority=args.priority,
                        created_by="kitelon-cli",
                    )
                self.session.last_job_id = job_id
                self.session.clear_cache()
                return self._success(f"Enqueued job #{job_id}")

            if args.job_cmd == "update":
                fields: dict[str, Any] = {}
                if args.priority is not None:
                    fields["priority"] = args.priority
                if args.target is not None:
                    fields["target"] = args.target
                if args.mode is not None:
                    fields["mode"] = args.mode
                if args.type is not None:
                    fields["job_type"] = args.type
                if args.workspace is not None:
                    fields["workspace"] = args.workspace
                if args.scheduled_at is not None:
                    fields["scheduled_at"] = args.scheduled_at
                if args.args is not None:
                    fields["args"] = json.loads(args.args)
                with get_connection() as conn:
                    update_job(conn, args.id, **fields)
                return self._success(f"Updated job #{args.id}")

            if args.job_cmd == "delete":
                with get_connection() as conn:
                    j = delete_job(conn, args.id, kill=args.kill)
                self.session.clear_cache()
                action = "Cancelled" if j.get("status") == "cancelled" else "Deleted"
                return self._success(f"{action} job #{j['id']}")

            if args.job_cmd == "retry":
                with get_connection() as conn:
                    new_id = retry_job(conn, args.id, created_by="kitelon-cli")
                self.session.last_job_id = new_id
                self.session.clear_cache()
                return self._success(f"Re-queued job {args.id} as new job #{new_id}")

            if args.job_cmd == "wait":
                job_id = args.id
                if args.last:
                    if self.session.last_job_id is None:
                        raise CliError("no last job in session")
                    job_id = self.session.last_job_id
                if job_id is None:
                    raise CliError("usage: jobs wait <ID> or jobs wait --last")
                job = wait_for_job(job_id)
                if job["status"] != "completed":
                    err = job.get("error_message") or job["status"]
                    return self._failure(f"job #{job_id} {job['status']}: {err}")
                return self._success(f"Job #{job_id} completed")
        except CliError as exc:
            return self._failure(str(exc))
        except ValueError as exc:
            return self._failure(str(exc))
        return self._failure("unknown jobs command")

    # --- schedule ---

    schedule_parser = Cmd2ArgumentParser()
    sched_sub = schedule_parser.add_subparsers(dest="sched_cmd", required=True)

    p = sched_sub.add_parser("list")
    p.add_argument("-w", "--workspace", choices_provider=workspace_choices_provider)

    p = sched_sub.add_parser("show")
    p.add_argument("id", type=int)

    p = sched_sub.add_parser("create")
    _workspace_arg(p, with_completion=True)
    p.add_argument("--cron", required=True, help='5-field cron (e.g. "0 2 * * *")')
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-m", dest="mode", default="normal", help="Scan mode", choices_provider=mode_choices_provider)
    _add_scan_option_flags(p)

    p = sched_sub.add_parser("delete")
    p.add_argument("id", type=int)

    @with_argparser(schedule_parser)
    @with_category("Schedules")
    def do_schedule(self, args: argparse.Namespace) -> bool:
        """Manage recurring scan schedules (cron)."""
        try:
            if args.sched_cmd == "list":
                with get_connection() as conn:
                    ws_id = None
                    if args.workspace:
                        ws = self._resolve_ws(args.workspace, required=True)
                        row = get_workspace_by_alias(conn, ws)
                        ws_id = int(row["id"]) if row else None
                    rows = list_schedules(conn, workspace_id=ws_id)
                for s in rows:
                    self.poutput(
                        f"{s['id']:4} {s.get('workspace_alias') or '-':15} "
                        f"{s['cron']:14} {s.get('target') or '-':20} {s.get('mode') or '-'}"
                    )
                return self._success()

            if args.sched_cmd == "show":
                with get_connection() as conn:
                    s = get_schedule(conn, args.id)
                if not s:
                    raise CliError(f"schedule not found: {args.id}")
                for label, key in (
                    ("id", "id"),
                    ("workspace", "workspace_alias"),
                    ("cron", "cron"),
                    ("target", "target"),
                    ("mode", "mode"),
                    ("next_run", "next_run_at"),
                    ("enabled", "enabled"),
                ):
                    self.poutput(f"{label:12} {s.get(key)!r}")
                return self._success()

            if args.sched_cmd == "create":
                workspace = self._resolve_ws(args.workspace, required=True)
                sched_id = create_scan_schedule(
                    workspace=workspace,
                    cron=args.cron,
                    target=args.target,
                    mode=args.mode,
                    options=build_scan_options(args),
                )
                self.session.clear_cache()
                return self._success(f"Created schedule #{sched_id}")

            if args.sched_cmd == "delete":
                with get_connection() as conn:
                    row = delete_schedule(conn, args.id)
                self.session.clear_cache()
                return self._success(f"Deleted schedule #{row['id']}")
        except CliError as exc:
            return self._failure(str(exc))
        except ValueError as exc:
            return self._failure(str(exc))
        return self._failure("unknown schedule command")

    # --- db ---

    db_parser = Cmd2ArgumentParser()
    db_sub = db_parser.add_subparsers(dest="db_cmd", required=True)
    db_sub.add_parser("migrate")
    db_sub.add_parser("test")
    db_sub.add_parser("prune-workspaces")
    db_sub.add_parser("fix-loot-layout")
    db_import = db_sub.add_parser("import", help="Import loot into PostgreSQL and rebuild reports")
    db_import.add_argument(
        "alias",
        nargs="?",
        help="Workspace alias (defaults to session workspace)",
    )
    db_import.add_argument(
        "--action",
        choices=("all", "import", "report"),
        default="all",
        help="Import only, reports only, or both (default)",
    )

    @with_argparser(db_parser)
    @with_category("Database")
    def do_db(self, args: argparse.Namespace) -> bool:
        """Database maintenance commands."""
        try:
            if args.db_cmd == "import":
                alias = args.alias or self._resolve_ws(None, required=True)
                msg = run_db_import(alias, action=args.action)
            else:
                msg = run_db_command(args.db_cmd)
            if "\n" in msg:
                self.poutput(msg)
            else:
                return self._success(msg)
            return self._success()
        except CliError as exc:
            return self._failure(str(exc))

    # --- rich help ---

    def help_scan(self) -> None:
        """Detailed scan modes and options."""
        self.poutput("Scan modes:")
        for mode in SCAN_MODES:
            self.poutput(f"  {mode['id']:14} {mode['description']}")
        self.poutput("\nScan options:")
        for opt in SCAN_OPTIONS:
            flag = opt.get("flag") or ""
            self.poutput(f"  {opt['id']:14} {flag:8} {opt['description']}")
        self.poutput("\nOSINT / recon (0.3.5):")
        self.poutput("  -o         whois, theHarvester; Shodan/Censys when SHODAN_API_KEY / CENSYS_* set")
        self.poutput("  -re        subfinder, dnsx, dnsrecon, gau (limits from kitelon.conf or preset)")
        self.poutput("  -pr NAME   osint-conservative (stock caps) or osint-deep (raised caps, metagoofil on)")
        self.poutput("\nExecution:")
        self.poutput("  (default)  enqueue background job (worker imports loot)")
        self.poutput("  --sync     run scan in foreground, import loot when done")
        self.poutput("  --wait     block until queued job completes")
        self.poutput("\nExample:")
        self.poutput("  scan -t example.com -w demo -m normal -o -re -pr osint-deep")
        self.poutput("\nFor argparse flags: scan -h")

    # --- completion ---

    @staticmethod
    def _completing_subcommand(line: str, beg: int) -> bool:
        """True when the cursor is still on the first argument (the subcommand name)."""
        prefix = line[:beg]
        tokens = prefix.split()
        if len(tokens) <= 1:
            return True
        return len(tokens) == 2 and not prefix.endswith((" ", "\t"))

    def complete_use(self, text: str, line: str, beg: int, end: int) -> Completions:
        return self.basic_complete(text, line, beg, end, workspace_aliases(self.session))

    def complete_workspace(self, text: str, line: str, beg: int, end: int) -> Completions:
        subcommands = ["list", "show", "create", "update", "delete", "rename-host"]
        if self._completing_subcommand(line, beg):
            return self.basic_complete(text, line, beg, end, subcommands)
        tokens = line[:beg].split()
        if len(tokens) >= 2 and tokens[1] == "show":
            # workspace show ssl [HOST]
            if len(tokens) >= 3 and tokens[2] == "ssl":
                alias = self._resolve_ws(None, required=False)
                if alias:
                    hosts = [r["hostname"] for r in list_workspace_ssl_scans(alias)]
                    return self.basic_complete(text, line, beg, end, hosts)
            # workspace show <ALIAS> ssl [HOST]
            if len(tokens) >= 4 and tokens[3] == "ssl":
                alias = tokens[2]
                try:
                    resolve_workspace(alias, required=True)
                except CliError:
                    return Completions()
                hosts = [r["hostname"] for r in list_workspace_ssl_scans(alias)]
                return self.basic_complete(text, line, beg, end, hosts)
            # workspace show <ALIAS>
            if len(tokens) == 3 or (len(tokens) >= 3 and tokens[2] != "ssl"):
                return self.basic_complete(text, line, beg, end, workspace_aliases(self.session))
        sub = line[:beg].split()[1]
        if sub in ("update", "delete", "rename-host"):
            return self.basic_complete(text, line, beg, end, workspace_aliases(self.session))
        return Completions()

    def complete_jobs(self, text: str, line: str, beg: int, end: int) -> Completions:
        subcommands = ["list", "show", "create", "delete", "retry", "update", "wait"]
        if self._completing_subcommand(line, beg):
            return self.basic_complete(text, line, beg, end, subcommands)
        sub = line[:beg].split()[1]
        if sub in ("show", "delete", "retry", "update", "wait") and not text.startswith("-"):
            return self.basic_complete(text, line, beg, end, recent_job_ids(self.session))
        if sub == "list":
            return self.basic_complete(text, line, beg, end, JOB_STATUSES)
        return Completions()

    def complete_schedule(self, text: str, line: str, beg: int, end: int) -> Completions:
        subcommands = ["list", "show", "create", "delete"]
        if self._completing_subcommand(line, beg):
            return self.basic_complete(text, line, beg, end, subcommands)
        sub = line[:beg].split()[1]
        if sub in ("show", "delete"):
            return self.basic_complete(text, line, beg, end, recent_schedule_ids(self.session))
        if sub == "create" and "--cron" in line:
            return self.basic_complete(text, line, beg, end, CRON_EXAMPLES)
        return Completions()

    def complete_db(self, text: str, line: str, beg: int, end: int) -> Completions:
        subcommands = ["migrate", "test", "import", "prune-workspaces", "fix-loot-layout"]
        if self._completing_subcommand(line, beg):
            return self.basic_complete(text, line, beg, end, subcommands)
        tokens = line[:beg].split()
        if len(tokens) >= 2 and tokens[1] == "import":
            return self.basic_complete(text, line, beg, end, workspace_aliases(self.session))
        return Completions()
