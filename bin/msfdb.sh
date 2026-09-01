#!/bin/bash
# Metasploit database helpers (sourced by install.sh and kitelon)

kitelon_msfdb_user() {
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        echo "$SUDO_USER"
        return 0
    fi
    if [[ $EUID -ne 0 ]]; then
        echo "${USER:-$(id -un)}"
        return 0
    fi
    local u
    u=$(logname 2>/dev/null || true)
    if [[ -n "$u" && "$u" != "root" ]]; then
        echo "$u"
        return 0
    fi
    return 1
}

kitelon_msfdb_port() {
    local user="$1"
    local conf="/home/$user/.msf4/db/postgresql.conf"
    if [[ -f "$conf" ]] && grep -qE '^port\s*=' "$conf"; then
        grep -E '^port\s*=' "$conf" | awk -F= '{print $2}' | tr -d ' '
    else
        echo 5433
    fi
}

kitelon_msfdb_port_in_use() {
    local port="$1"
    ss -tln 2>/dev/null | grep -q ":${port} "
}

# Suppress noisy RubyGems spec warnings from msfdb (harmless upstream noise).
kitelon_msfdb_filter_ruby_noise() {
    grep -v -E \
        '^WARN: (Unresolved or ambiguous specs during Gem::Specification\.reset:|Clearing out unresolved specs\.)' \
        | grep -v -E \
        '^Please report a bug if this causes problems\.$|^      (base64|logger|Available/installed|- )' \
        || true
}

kitelon_msfdb_exec() {
    local user="$1"
    local out_file="$2"
    shift 2
    local rc=0

    if [[ $EUID -eq 0 ]]; then
        if command -v runuser &>/dev/null; then
            runuser -u "$user" -- env RUBYOPT="-W0" msfdb "$@" >"$out_file" 2>&1 || rc=$?
        else
            sudo -u "$user" -H env RUBYOPT="-W0" msfdb "$@" >"$out_file" 2>&1 || rc=$?
        fi
    else
        env RUBYOPT="-W0" msfdb "$@" >"$out_file" 2>&1 || rc=$?
    fi
    return $rc
}

kitelon_msfdb_run() {
    local user="$1"
    shift
    local out_file rc=0
    out_file=$(mktemp /tmp/kitelon-msfdb-out.XXXXXX 2>/dev/null || echo /tmp/kitelon-msfdb-out.$$)

    kitelon_msfdb_exec "$user" "$out_file" "$@" || rc=$?
    kitelon_msfdb_filter_ruby_noise < "$out_file"
    rm -f "$out_file"
    return $rc
}

kitelon_msfdb_db_running() {
    local user="$1"
    local port db_dir
    port=$(kitelon_msfdb_port "$user")
    db_dir="/home/$user/.msf4/db"

    if kitelon_msfdb_pg_ctl "$user" -D "$db_dir" status &>/dev/null; then
        return 0
    fi

    if kitelon_msfdb_port_in_use "$port"; then
        ss -tlnp 2>/dev/null | grep ":${port} " | grep -q "$user"
        return $?
    fi

    return 1
}

kitelon_msfdb_pg_ctl() {
    local user="$1"
    shift
    local pg_ctl=""
    if [[ -x /opt/metasploit-framework/embedded/bin/pg_ctl ]]; then
        pg_ctl=/opt/metasploit-framework/embedded/bin/pg_ctl
    else
        pg_ctl=$(command -v pg_ctl 2>/dev/null || true)
    fi
    [[ -n "$pg_ctl" ]] || return 1
    if [[ $EUID -eq 0 ]]; then
        runuser -u "$user" -- "$pg_ctl" "$@"
    else
        "$pg_ctl" "$@"
    fi
}

kitelon_msfdb_kill_port() {
    local port="$1"
    local user="$2"
    local pid owner

    pid=$(ss -tlnp 2>/dev/null | grep ":${port} " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
    if [[ -n "$pid" ]]; then
        owner=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
        if [[ -z "$owner" || "$owner" == "$user" ]]; then
            kl_msg_info "Stopping process on port ${port} (PID ${pid})..."
            kill "$pid" 2>/dev/null || true
            sleep 1
            kill -9 "$pid" 2>/dev/null || true
            sleep 1
            return 0
        fi
    fi

    if [[ $EUID -eq 0 ]] && command -v fuser &>/dev/null; then
        fuser -k "${port}/tcp" 2>/dev/null || true
        sleep 1
    fi
}

kitelon_msfdb_recover() {
    local user="$1"
    local db_dir="/home/$user/.msf4/db"
    local port
    port=$(kitelon_msfdb_port "$user")

    [[ -d "$db_dir" ]] || return 0
    kitelon_msfdb_port_in_use "$port" || return 0

    if [[ -f "$db_dir/postmaster.pid" ]]; then
        if ! kitelon_msfdb_pg_ctl "$user" -D "$db_dir" status &>/dev/null; then
            kl_msg_info "Stale postmaster.pid: stopping MSF DB..."
            kitelon_msfdb_pg_ctl "$user" -D "$db_dir" stop -m fast 2>/dev/null || true
            rm -f "$db_dir/postmaster.pid" 2>/dev/null || true
        else
            return 0
        fi
    else
        kl_msg_info "MSF DB port ${port} is in use but postmaster.pid is missing: recovering stale server..."
    fi

    local out_file
    out_file=$(mktemp /tmp/kitelon-msfdb-out.XXXXXX 2>/dev/null || echo /tmp/kitelon-msfdb-out.$$)
    kitelon_msfdb_exec "$user" "$out_file" stop >/dev/null 2>&1 || true
    rm -f "$out_file"
    kitelon_msfdb_pg_ctl "$user" -D "$db_dir" stop -m fast 2>/dev/null || true
    pkill -u "$user" -f "$db_dir" 2>/dev/null || true
    sleep 1

    if kitelon_msfdb_port_in_use "$port"; then
        kitelon_msfdb_kill_port "$port" "$user"
    fi
}

kitelon_msfdb_running() {
    local user="$1"
    local out_file rc=0
    out_file=$(mktemp /tmp/kitelon-msfdb-out.XXXXXX 2>/dev/null || echo /tmp/kitelon-msfdb-out.$$)

    kitelon_msfdb_exec "$user" "$out_file" status || rc=$?
    if grep -qE 'Database (is running|started|already started)' "$out_file" 2>/dev/null; then
        rm -f "$out_file"
        return 0
    fi
    rm -f "$out_file"

    kitelon_msfdb_db_running "$user"
}

kitelon_msfdb_setup() {
    command -v msfdb &>/dev/null || return 0

    local user
    user=$(kitelon_msfdb_user) || {
        kl_msg_warn "Cannot determine user for Metasploit DB: skipping msfdb setup"
        return 1
    }

    service postgresql start 2>/dev/null || true

    if kitelon_msfdb_running "$user"; then
        kl_msg_ok "Metasploit DB already running (user: ${user})"
        return 0
    fi

    kitelon_msfdb_recover "$user"

    local db_dir="/home/$user/.msf4/db"
    local has_db=0
    [[ -d "$db_dir/base" || -f "/home/$user/.msf4/database.yml" ]] && has_db=1

    if [[ "$has_db" -eq 1 ]]; then
        kl_msg_info "Starting existing Metasploit DB as ${user}..."
        kitelon_msfdb_run "$user" start || true
    else
        kl_msg_info "Initializing Metasploit DB as ${user}..."
        kitelon_msfdb_run "$user" init || true
    fi

    if kitelon_msfdb_running "$user"; then
        kl_msg_ok "Metasploit DB ready (user: ${user})"
        return 0
    fi

    kl_msg_warn "Metasploit DB is not running (user: ${user})"
    kl_msg_warn "  Log: /home/${user}/.msf4/db/log"
    kl_msg_warn "  Fix: run as ${user}: msfdb stop && msfdb start"
    kl_msg_warn "  Or: msfdb reinit  (rebuilds DB; local MSF data is lost)"
    return 1
}
