-- Kitelon: store workspace loot files and generated reports in PostgreSQL

CREATE TABLE IF NOT EXISTS loot_artifacts (
    id SERIAL PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    rel_path TEXT NOT NULL,
    content BYTEA NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    size_bytes BIGINT NOT NULL,
    sha256 TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (workspace_id, rel_path)
);

CREATE INDEX IF NOT EXISTS idx_loot_artifacts_workspace ON loot_artifacts(workspace_id);
CREATE INDEX IF NOT EXISTS idx_loot_artifacts_updated ON loot_artifacts(workspace_id, updated_at DESC);
