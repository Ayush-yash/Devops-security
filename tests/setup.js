const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

let realPool = null;
if (process.env.TEST_DATABASE_URL) {
    realPool = new Pool({ connectionString: process.env.TEST_DATABASE_URL });
}

// Global mocks
jest.mock('../db', () => {
    const { Pool } = require('pg');
    let innerPool = null;
    if (process.env.TEST_DATABASE_URL) {
        innerPool = new Pool({ connectionString: process.env.TEST_DATABASE_URL });
    }

    const mockQuery = jest.fn().mockImplementation(async (text, params) => {
        if (innerPool) {
            return await innerPool.query(text, params);
        }
        // Default stub return for mock testing
        return { rows: [], rowCount: 0 };
    });

    const mockInit = jest.fn().mockImplementation(async () => {
        if (innerPool) {
            const fs = require('fs');
            const path = require('path');
            const client = await innerPool.connect();
            try {
                // Check if tenants exists
                const checkRes = await client.query(`
                    SELECT EXISTS (
                        SELECT FROM pg_tables 
                        WHERE schemaname = 'public' 
                        AND tablename  = 'tenants'
                    );
                `);
                if (!checkRes.rows[0].exists) {
                    const initSql = fs.readFileSync(path.join(__dirname, '../db/init.sql'), 'utf8');
                    await client.query(initSql);
                }
            } finally {
                client.release();
            }
        }
    });

    return {
        pool: innerPool || {
            on: jest.fn(),
            end: jest.fn().mockResolvedValue(),
            connect: jest.fn().mockResolvedValue({
                query: jest.fn().mockResolvedValue({ rows: [] }),
                release: jest.fn()
            })
        },
        query: mockQuery,
        initDatabase: mockInit
    };
});

// Suppress console logs in tests for cleaner output
if (process.env.NODE_ENV === 'test') {
    const logger = require('../logger');
    logger.silent = true;

    // Globally mock fetch to ensure tests remain offline and use the fallback engine
    global.fetch = jest.fn().mockImplementation((url) => {
        if (url.includes('/v1/data/devsecops/security_gate')) {
            return Promise.reject(new Error('OPA Offline'));
        }
        return Promise.resolve({
            ok: true,
            status: 200,
            json: async () => ({})
        });
    });
}
