-- Kitelon enriched loot tables

CREATE TABLE IF NOT EXISTS services (
    id SERIAL PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    product TEXT,
    version TEXT,
    cpe TEXT,
    UNIQUE (workspace_id, hostname, port, protocol)
);

CREATE TABLE IF NOT EXISTS web_endpoints (
    id SERIAL PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    port INTEGER,
    url TEXT NOT NULL,
    status_code INTEGER,
    title TEXT,
    screenshot_path TEXT,
    UNIQUE (workspace_id, url)
);

CREATE TABLE IF NOT EXISTS discovered_urls (
    id SERIAL PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    url TEXT NOT NULL,
    source TEXT NOT NULL,
    status_code INTEGER,
    UNIQUE (workspace_id, url, source)
);

CREATE TABLE IF NOT EXISTS technologies (
    id SERIAL PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    port INTEGER,
    name TEXT NOT NULL,
    version TEXT,
    UNIQUE (workspace_id, hostname, port, name)
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id SERIAL PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    scan_id TEXT,
    mode TEXT,
    target TEXT,
    options_json JSONB NOT NULL DEFAULT '{}',
    steps_json JSONB NOT NULL DEFAULT '[]',
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS source TEXT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cve TEXT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cwe TEXT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS discovered_at TIMESTAMPTZ;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS artifact_path TEXT;

CREATE INDEX IF NOT EXISTS idx_services_workspace ON services(workspace_id);
CREATE INDEX IF NOT EXISTS idx_web_endpoints_workspace ON web_endpoints(workspace_id);
CREATE INDEX IF NOT EXISTS idx_discovered_urls_workspace ON discovered_urls(workspace_id);
CREATE INDEX IF NOT EXISTS idx_technologies_workspace ON technologies(workspace_id);
CREATE INDEX IF NOT EXISTS idx_scan_runs_workspace ON scan_runs(workspace_id);
