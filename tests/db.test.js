const db = require('../db');

describe('Database Integration Tests', () => {
    // If TEST_DATABASE_URL is set, we run real PostgreSQL integration tests.
    // Otherwise, we verify the interface methods are present and correct.
    const runIntegration = !!process.env.TEST_DATABASE_URL;

    test('Database interface has pool, query and initDatabase', () => {
        expect(db.pool).toBeDefined();
        expect(typeof db.query).toBe('function');
        expect(typeof db.initDatabase).toBe('function');
    });

    if (runIntegration) {
        test('Can initialize database and run basic queries', async () => {
            await db.initDatabase();
            
            // Insert test tenant and project
            const tenantId = '00000000-0000-0000-0000-000000000000';
            const projectName = 'db-integration-test-project';
            
            // Cleanup existing if left over
            await db.query('DELETE FROM projects WHERE name = $1', [projectName]);
            
            const insertRes = await db.query(
                'INSERT INTO projects (tenant_id, name, repository_url) VALUES ($1, $2, $3) RETURNING id',
                [tenantId, projectName, 'https://github.com/shieldops/db-integration-test']
            );
            expect(insertRes.rows.length).toBe(1);
            const projectId = insertRes.rows[0].id;
            
            const selectRes = await db.query('SELECT * FROM projects WHERE id = $1', [projectId]);
            expect(selectRes.rows.length).toBe(1);
            expect(selectRes.rows[0].name).toBe(projectName);
            
            // Cleanup
            await db.query('DELETE FROM projects WHERE id = $1', [projectId]);
        });

        test('Handles query failures gracefully', async () => {
            await expect(db.query('SELECT * FROM table_that_does_not_exist')).rejects.toThrow();
        });
    } else {
        test('Mocked database query returns stub data', async () => {
            const res = await db.query('SELECT * FROM projects');
            expect(res.rows).toBeDefined();
            expect(Array.isArray(res.rows)).toBe(true);
        });
    }
});
