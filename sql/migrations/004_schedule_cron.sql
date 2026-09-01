-- Migrate legacy cadence column to cron (no-op on fresh installs).

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'job_schedules'
          AND column_name = 'cadence'
    ) THEN
        ALTER TABLE job_schedules RENAME COLUMN cadence TO cron;
    END IF;
END $$;

UPDATE job_schedules SET cron = '0 0 * * *' WHERE cron = 'daily';
UPDATE job_schedules SET cron = '0 0 * * 0' WHERE cron = 'weekly';
UPDATE job_schedules SET cron = '0 0 1 * *' WHERE cron = 'monthly';
