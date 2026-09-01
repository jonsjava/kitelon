#!/bin/bash
# Kitelon container entrypoint: config, DB wait, migrations, role dispatch.

set -euo pipefail

INSTALL_DIR="${KITELON_INSTALL_DIR:-/usr/share/kitelon}"
export KITELON_INSTALL_DIR="$INSTALL_DIR"
export PYTHONPATH="${INSTALL_DIR}/bin${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:${PATH}"

kitelon_log() {
    echo "[kitelon-entrypoint] $*"
}

write_db_secrets() {
    local secrets="/root/.kitelon_db.conf"
    if [[ -z "${DB_PASSWORD:-}" ]]; then
        kitelon_log "DB_PASSWORD is not set: PostgreSQL auth will fail"
        return 1
    fi
    cat >"$secrets" <<EOF
# Kitelon PostgreSQL password (generated at container start)
DB_PASSWORD=${DB_PASSWORD}
EOF
    chmod 600 "$secrets"
}

patch_root_config() {
    local conf="/root/.kitelon.conf"
    if [[ ! -f "$conf" && -f "$INSTALL_DIR/kitelon.conf" ]]; then
        cp "$INSTALL_DIR/kitelon.conf" "$conf"
    fi
    [[ -f "$conf" ]] || return 0

    local key val
    for key in DB_HOST DB_PORT DB_NAME DB_USER DB_ENABLED WEB_BIND WEB_PORT LOG_DIR; do
        val="${!key:-}"
        [[ -n "$val" ]] || continue
        if grep -q "^${key}=" "$conf"; then
            sed -i "s|^${key}=.*|${key}=\"${val}\"|" "$conf"
        else
            echo "${key}=\"${val}\"" >>"$conf"
        fi
    done
}

write_api_keys() {
    local keys="/root/.kitelon_api_keys.conf"
    if [[ -z "${WEB_API_KEY:-}" && -f "$keys" ]]; then
        # shellcheck disable=SC1090
        source "$keys"
    fi
    if [[ -z "${WEB_API_KEY:-}" ]]; then
        WEB_API_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
        kitelon_log "generated WEB_API_KEY (stored in $keys)"
    fi
    export WEB_API_KEY
    printf 'WEB_API_KEY=%s\n' "$WEB_API_KEY" >"$keys"
    chmod 600 "$keys"
}

wait_for_postgres() {
    local attempts="${DB_WAIT_ATTEMPTS:-60}"
    local delay="${DB_WAIT_DELAY_SEC:-2}"
    kitelon_log "waiting for PostgreSQL at ${DB_HOST:-postgres}:${DB_PORT:-5432}..."
    python3 - <<'PY'
import os, sys, time

try:
    import psycopg
except ImportError:
    sys.exit("psycopg not installed")

host = os.environ.get("DB_HOST", "postgres")
port = int(os.environ.get("DB_PORT", "5432"))
dbname = os.environ.get("DB_NAME", "kitelon")
user = os.environ.get("DB_USER", "kitelon")
password = os.environ.get("DB_PASSWORD", "")
attempts = int(os.environ.get("DB_WAIT_ATTEMPTS", "60"))
delay = float(os.environ.get("DB_WAIT_DELAY_SEC", "2"))

for i in range(attempts):
    try:
        with psycopg.connect(
            host=host, port=port, dbname=dbname, user=user, password=password, connect_timeout=3
        ):
            sys.exit(0)
    except Exception as exc:
        if i + 1 >= attempts:
            print(f"PostgreSQL not ready after {attempts} attempts: {exc}", file=sys.stderr)
            sys.exit(1)
        time.sleep(delay)
PY
}

run_migrations() {
    kitelon_log "running database migrations..."
    python3 "$INSTALL_DIR/bin/kitelon_db.py" migrate
}

bootstrap() {
    mkdir -p "$INSTALL_DIR/loot/workspace" /var/log/kitelon
    write_db_secrets
    patch_root_config
    write_api_keys
    if [[ "${DB_ENABLED:-1}" != "0" ]]; then
        wait_for_postgres
        run_migrations
    fi
}

run_web() {
    export WEB_BIND="${WEB_BIND:-0.0.0.0}"
    export WEB_PORT="${WEB_PORT:-8080}"
    export WEB_API_KEY="${WEB_API_KEY:-}"
    if [[ -z "$WEB_API_KEY" && -f /root/.kitelon_api_keys.conf ]]; then
        # shellcheck disable=SC1091
        source /root/.kitelon_api_keys.conf
    fi
    export KITELON_WEB_ROOT="$INSTALL_DIR/web"
    export KITELON_LOOT_ROOT="$INSTALL_DIR/loot"
    kitelon_log "starting Web UI on ${WEB_BIND}:${WEB_PORT}"
    exec python3 "$INSTALL_DIR/bin/kitelon_api.py"
}

run_worker() {
    export WORKER_ROLE="${WORKER_ROLE:-both}"
    export WORKER_POLL_SEC="${WORKER_POLL_SEC:-10}"
    export WORKER_POST_CONCURRENCY="${WORKER_POST_CONCURRENCY:-2}"
    kitelon_log "starting job worker (role=${WORKER_ROLE})"
    exec python3 "$INSTALL_DIR/bin/kitelon_worker.py" run
}

run_recover_loop() {
    kitelon_log "starting recover loop (every ${RECOVER_INTERVAL_SEC:-300}s)"
    while true; do
        python3 "$INSTALL_DIR/bin/kitelon_worker.py" recover || true
        sleep "${RECOVER_INTERVAL_SEC:-300}"
    done
}

run_scan() {
    exec "$INSTALL_DIR/kitelon" "$@"
}

run_cli() {
    exec python3 "$INSTALL_DIR/bin/kitelon_cli.py" "$@"
}

print_help() {
    cat <<'EOF'
Kitelon container commands:
  web            Start Web UI + REST API (default compose service)
  worker         Start PostgreSQL job worker
  recover-loop   Periodic stuck-job recovery (compose sidecar)
  migrate        Run DB migrations only
  scan           Run kitelon scan CLI (pass args after --)
  cli            Run kitelon-cli REPL or subcommands
  help           Show this message

Examples:
  docker compose up -d
  docker compose run --rm kitelon scan -- -t example.com -w demo
  docker compose exec kitelon cli
EOF
}

main() {
    local cmd="${1:-help}"
    shift || true

    case "$cmd" in
        web|worker|recover-loop|migrate|scan|cli)
            bootstrap
            ;;
        help|-h|--help)
            print_help
            exit 0
            ;;
        *)
            bootstrap
            run_scan "$cmd" "$@"
            exit 0
            ;;
    esac

    case "$cmd" in
        web) run_web ;;
        worker) run_worker ;;
        recover-loop) run_recover_loop ;;
        migrate) ;;
        scan)
            if [[ "${1:-}" == "--" ]]; then
                shift
            fi
            run_scan "$@"
            ;;
        cli) run_cli "$@" ;;
    esac
}

main "$@"
