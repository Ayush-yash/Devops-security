const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
const logger = require('./logger');
require('dotenv').config();

const connectionString = process.env.DATABASE_URL;

const pool = new Pool({
    connectionString,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
});

// Database connection recovery / error handling on idle clients
pool.on('error', (err) => {
    logger.error("Unexpected error on idle database client", { error: err.message, stack: err.stack });
});

async function initDatabase() {
    let client;
    let retries = 5;
    while (retries > 0) {
        try {
            client = await pool.connect();
            logger.info("Connected to PostgreSQL successfully!");
            break;
        } catch (err) {
            retries--;
            logger.warn(`PostgreSQL connection failed. Retries remaining: ${retries}`, { error: err });
            if (retries === 0) {
                logger.error("Failed to connect to PostgreSQL. Exiting...");
                throw err;
            }
            await new Promise(res => setTimeout(res, 2000));
        }
    }

    try {
        // Check if tenants table exists
        const checkTableRes = await client.query(`
            SELECT EXISTS (
                SELECT FROM pg_tables 
                WHERE schemaname = 'public' 
                AND tablename  = 'tenants'
            );
        `);

        if (!checkTableRes.rows[0].exists) {
            logger.info("Database schema not found. Loading init.sql migration...");
            const initSqlPath = path.join(__dirname, 'db', 'init.sql');
            const initSql = fs.readFileSync(initSqlPath, 'utf8');
            await client.query(initSql);
            logger.info("Schema initialized successfully and default values seeded.");
        } else {
            logger.info("Database schema already exists. Skipping initialization.");
        }
            
        // Phase 8: Ensure waivers table exists
        const checkWaiversRes = await client.query(`
                SELECT EXISTS (
                    SELECT FROM pg_tables 
                    WHERE schemaname = 'public' 
                    AND tablename  = 'waivers'
                );
            `);
            if (!checkWaiversRes.rows[0].exists) {
                logger.info("Waivers table not found. Running Phase 8 migrations...");
                await client.query(`
                    DO $$ 
                    BEGIN 
                        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'waiver_status') THEN
                            CREATE TYPE waiver_status AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED');
                        END IF;
                    END $$;

                    CREATE TABLE IF NOT EXISTS waivers (
                        id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        vulnerability_id VARCHAR(64) NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
                        requester_email VARCHAR(320) NOT NULL,
                        approver_email  VARCHAR(320),
                        reason          TEXT NOT NULL,
                        status          waiver_status NOT NULL DEFAULT 'PENDING',
                        expires_at      TIMESTAMPTZ NOT NULL,
                        created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
                        updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                `);
                logger.info("Waivers migration complete.");
            }

            // Phase 9: Ensure pipeline_logs table exists
            const checkLogsRes = await client.query(`
                SELECT EXISTS (
                    SELECT FROM pg_tables 
                    WHERE schemaname = 'public' 
                    AND tablename  = 'pipeline_logs'
                );
            `);
            if (!checkLogsRes.rows[0].exists) {
                logger.info("pipeline_logs table not found. Running Phase 9 migrations...");
                await client.query(`
                    CREATE TABLE IF NOT EXISTS pipeline_logs (
                        id              BIGSERIAL PRIMARY KEY,
                        pipeline_id     VARCHAR(64) NOT NULL REFERENCES pipelines(id) ON DELETE CASCADE,
                        stage           VARCHAR(64) NOT NULL,
                        severity        VARCHAR(64) NOT NULL,
                        message         TEXT NOT NULL,
                        details         JSONB DEFAULT '{}',
                        created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                `);
                logger.info("Pipeline Logs migration complete.");
            }

            // Phase 12: Ensure notification_events table exists
            const checkNotifsRes = await client.query(`
                SELECT EXISTS (
                    SELECT FROM pg_tables 
                    WHERE schemaname = 'public' 
                    AND tablename  = 'notification_events'
                );
            `);
            if (!checkNotifsRes.rows[0].exists) {
                logger.info("notification_events table not found. Running Phase 12 migrations...");
                await client.query(`
                    CREATE TABLE IF NOT EXISTS notification_events (
                        id              BIGSERIAL PRIMARY KEY,
                        channel         VARCHAR(64) NOT NULL,
                        event_type      VARCHAR(64) NOT NULL,
                        payload         JSONB NOT NULL,
                        status          VARCHAR(64) NOT NULL DEFAULT 'PENDING',
                        error_msg       TEXT,
                        retry_count     INT NOT NULL DEFAULT 0,
                        created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
                        updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                `);
                logger.info("Notification Events migration complete.");
            }

            // Phase 13: Ensure scan_jobs table exists
            const checkJobsRes = await client.query(`
                SELECT EXISTS (
                    SELECT FROM pg_tables 
                    WHERE schemaname = 'public' 
                    AND tablename  = 'scan_jobs'
                );
            `);
            if (!checkJobsRes.rows[0].exists) {
                logger.info("scan_jobs table not found. Running Phase 13 migrations...");
                await client.query(`
                    CREATE TABLE IF NOT EXISTS scan_jobs (
                        id              BIGSERIAL PRIMARY KEY,
                        pipeline_id     VARCHAR(64) NOT NULL UNIQUE,
                        status          VARCHAR(64) NOT NULL DEFAULT 'PENDING',
                        error_msg       TEXT,
                        retry_count     INT NOT NULL DEFAULT 0,
                        created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
                        updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                `);
                
                // Add NOTIFY trigger for pipeline_logs so worker can trigger SSE in server
                await client.query(`
                    CREATE OR REPLACE FUNCTION notify_pipeline_log() RETURNS TRIGGER AS $$
                    BEGIN
                        PERFORM pg_notify('pipeline_logs_channel', row_to_json(NEW)::text);
                        RETURN NEW;
                    END;
                    $$ LANGUAGE plpgsql;

                    DROP TRIGGER IF EXISTS pipeline_logs_notify_trigger ON pipeline_logs;
                    CREATE TRIGGER pipeline_logs_notify_trigger
                    AFTER INSERT ON pipeline_logs
                    FOR EACH ROW EXECUTE PROCEDURE notify_pipeline_log();
                `);
                
                logger.info("Scan Jobs migration complete.");
            }
    } catch (err) {
        logger.error("Error running database migrations", { error: err });
        throw err;
    } finally {
        if (client) client.release();
    }
}

module.exports = {
    pool,
    query: (text, params) => pool.query(text, params),
    initDatabase
};
