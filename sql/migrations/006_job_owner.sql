-- Record which host (or container) claimed a running job, so recover only
-- trusts and signals a job's PID from the same PID namespace.

ALTER TABLE jobs ADD COLUMN IF NOT EXISTS worker_host TEXT;
