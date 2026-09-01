-- Kitelon core PostgreSQL schema

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS workspaces (
    id SERIAL PRIMARY KEY,
    alias TEXT NOT NULL UNIQUE,
    loot_path TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_imported_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS hosts (
    id SERIAL PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    ip TEXT,
    mac TEXT,
    os_guess TEXT,
    is_live INTEGER NOT NULL DEFAULT 0,
    risk_score REAL NOT NULL DEFAULT 0,
    open_ports TEXT,
    web_title TEXT,
    UNIQUE (workspace_id, hostname)
);

CREATE TABLE IF NOT EXISTS domains (
    id SERIAL PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    fqdn TEXT NOT NULL,
    is_target INTEGER NOT NULL DEFAULT 0,
    UNIQUE (workspace_id, fqdn)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    severity TEXT NOT NULL,
    name TEXT NOT NULL,
    url TEXT,
    evidence TEXT,
    source_file TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    message TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS workspace_stats (
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (workspace_id, key)
);

CREATE TABLE IF NOT EXISTS jobs (
    id SERIAL PRIMARY KEY,
    workspace_id INTEGER REFERENCES workspaces(id) ON DELETE SET NULL,
    job_type TEXT NOT NULL,
    target TEXT,
    mode TEXT,
    args_json JSONB NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',
    priority INTEGER NOT NULL DEFAULT 100,
    scheduled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    pid INTEGER,
    exit_code INTEGER,
    error_message TEXT,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS job_schedules (
    id SERIAL PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    cron TEXT NOT NULL,
    target TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'normal',
    args_json JSONB NOT NULL DEFAULT '{}',
    next_run_at TIMESTAMPTZ NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS worker_heartbeat (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    last_tick_at TIMESTAMPTZ,
    last_job_id INTEGER,
    message TEXT
);

INSERT INTO worker_heartbeat (id) VALUES (1) ON CONFLICT DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_hosts_workspace ON hosts(workspace_id);
CREATE INDEX IF NOT EXISTS idx_domains_workspace ON domains(workspace_id);
CREATE INDEX IF NOT EXISTS idx_vulns_workspace ON vulnerabilities(workspace_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_hostname ON vulnerabilities(hostname);
CREATE INDEX IF NOT EXISTS idx_jobs_status_sched ON jobs(status, scheduled_at);
CREATE INDEX IF NOT EXISTS idx_schedules_next ON job_schedules(next_run_at) WHERE enabled = TRUE;
