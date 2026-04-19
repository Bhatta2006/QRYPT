-- =============================================================================
-- SVT System — PostgreSQL Initialization Script
-- Runs once on first container start
-- =============================================================================

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create application database (if not created by POSTGRES_DB env)
-- Note: This script runs against the default DB; the svt DB is created by env var
SELECT 'SVT Database initialization started' AS status;

-- Create the non-superuser application role
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'svt_app') THEN
        CREATE ROLE svt_app WITH
            LOGIN
            PASSWORD 'local_app_db_123'
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE;
        RAISE NOTICE 'Role svt_app created';
    ELSE
        RAISE NOTICE 'Role svt_app already exists';
    END IF;
END
$$;

-- Grant connection to the svt database
GRANT CONNECT ON DATABASE svt TO svt_app;

-- Grant schema usage (Alembic will handle table-level grants)
GRANT USAGE ON SCHEMA public TO svt_app;

-- Allow svt_app to create tables (needed for Alembic migrations)
GRANT CREATE ON SCHEMA public TO svt_app;

-- Default privileges: auto-grant on future tables created in public schema
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO svt_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO svt_app;

SELECT 'SVT Database initialization completed' AS status;
