const request = require('supertest');
const app = require('../server');
const db = require('../db');
const crypto = require('crypto');

describe('API Integration Tests', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    describe('System Health Routes', () => {
        test('GET /health returns 200 and liveness status', async () => {
            const res = await request(app).get('/health');
            expect(res.status).toBe(200);
            expect(res.body.status).toBe('UP');
        });

        test('GET /ready returns 200 when database is responsive', async () => {
            db.query.mockResolvedValueOnce({ rows: [{ 1: 1 }] });
            const res = await request(app).get('/ready');
            expect(res.status).toBe(200);
            expect(res.body.status).toBe('READY');
        });

        test('GET /ready returns 503 when database query fails (failure case: database unavailable)', async () => {
            db.query.mockRejectedValueOnce(new Error('PostgreSQL Connection Timeout'));
            const res = await request(app).get('/ready');
            expect(res.status).toBe(503);
            expect(res.body.status).toBe('NOT_READY');
        });

        test('GET /metrics returns 200 and Prometheus text format metrics', async () => {
            db.query.mockResolvedValueOnce({ rows: [] }); // query active findings count
            const res = await request(app).get('/metrics');
            expect(res.status).toBe(200);
            expect(res.text).toContain('http_requests_total');
        });

        test('All responses include X-Correlation-ID header', async () => {
            const res = await request(app).get('/health');
            expect(res.headers['x-correlation-id']).toBeDefined();
        });
    });

    describe('Authentication & RBAC Controls', () => {
        test('GET /api/v1/findings fails with 401 when X-User-Role is missing', async () => {
            const res = await request(app).get('/api/v1/findings');
            expect(res.status).toBe(401);
            expect(res.body.error).toContain('Missing X-User-Role header');
        });

        test('POST /api/v1/policies blocks DEVELOPER role with 403 Forbidden', async () => {
            const res = await request(app)
                .post('/api/v1/policies')
                .set('X-User-Role', 'DEVELOPER')
                .send({ criticalBlock: true });
            expect(res.status).toBe(403);
            expect(res.body.error).toContain('Forbidden');
        });

        test('POST /api/v1/policies allows ADMIN and updates settings', async () => {
            db.query.mockResolvedValueOnce({ rows: [] }); // insert success
            db.query.mockResolvedValueOnce({ rows: [] }); // audit log success
            db.query.mockResolvedValueOnce({ rows: [{ key: 'criticalBlock', value: true }] }); // select success
            const res = await request(app)
                .post('/api/v1/policies')
                .set('X-User-Role', 'ADMIN')
                .send({ criticalBlock: true });
            expect(res.status).toBe(200);
            expect(res.body.policies.criticalBlock).toBe(true);
        });
    });

    describe('Findings Management API', () => {
        test('GET /api/v1/findings fetches list of open findings', async () => {
            db.query.mockResolvedValueOnce({
                rows: [
                    { id: 'V1', cve: 'CVE-1234', title: 'Dependency Vulnerability', severity: 'CRITICAL', status: 'OPEN' }
                ]
            });
            const res = await request(app)
                .get('/api/v1/findings')
                .set('X-User-Role', 'DEVELOPER');
            expect(res.status).toBe(200);
            expect(res.body.length).toBe(1);
            expect(res.body[0].id).toBe('V1');
        });
    });

    describe('Waiver Workflow Endpoints', () => {
        test('POST /api/v1/waive/:id/request creates a pending waiver', async () => {
            db.query.mockResolvedValueOnce({ rows: [{ id: 'V1', project_id: 'P1', severity: 'CRITICAL', cve: 'CVE-1234', project: 'test-project' }] }); // select vuln
            db.query.mockResolvedValueOnce({ rows: [{ id: 'W1' }] }); // insert waiver (RETURNING id)
            db.query.mockResolvedValueOnce({ rows: [] }); // insert audit log

            const res = await request(app)
                .post('/api/v1/waive/V1/request')
                .set('X-User-Role', 'DEVELOPER')
                .send({ reason: 'Legacy library deprecation bypass', expires_in_days: 15 });

            expect(res.status).toBe(200);
            expect(res.body.status).toBe('success');
            expect(res.body.waiver_id).toBe('W1');
        });
    });

    describe('GitHub Webhook & Verification Gates', () => {
        const secret = 'test_webhook_secret';
        const payload = {
            ref: 'refs/heads/main',
            after: 'abcdef1234567890',
            repository: { html_url: 'https://github.com/org/test-project' },
            pusher: { name: 'test-user' }
        };
        const bodyString = JSON.stringify(payload);
        const deliveryId = 'delivery-992';

        beforeEach(() => {
            process.env.GITHUB_WEBHOOK_SECRET = secret;
        });

        afterEach(() => {
            delete process.env.GITHUB_WEBHOOK_SECRET;
        });

        test('Webhook rejects requests with invalid signatures (failure case: invalid webhook)', async () => {
            db.query.mockResolvedValueOnce({ rows: [] }); // idempotency check
            db.query.mockResolvedValueOnce({ rows: [{ id: 'P1', name: 'test-project', github_webhook_secret: secret }] }); // get project

            const res = await request(app)
                .post('/api/v1/webhooks/github')
                .set('X-GitHub-Event', 'push')
                .set('X-GitHub-Delivery', deliveryId)
                .set('X-Hub-Signature-256', 'sha256=invalidmac')
                .send(payload);

            expect(res.status).toBe(401);
            expect(res.body.error).toContain('Signature verification failed');
        });

        test('Webhook successfully processes valid payload signature', async () => {
            // Mock DB checks
            db.query.mockResolvedValueOnce({ rows: [] }); // idempotency check: no duplicate
            db.query.mockResolvedValueOnce({ rows: [{ id: 'P1', name: 'test-project', github_webhook_secret: secret }] }); // get project
            db.query.mockResolvedValueOnce({ rows: [] }); // duplicate check pipeline: no active pipeline
            db.query.mockResolvedValueOnce({ rows: [] }); // insert processed webhook
            db.query.mockResolvedValueOnce({ rows: [] }); // insert pipeline run
            db.query.mockResolvedValueOnce({ rows: [] }); // insert audit log
            db.query.mockResolvedValueOnce({ rows: [] }); // insert scan job

            const hmac = crypto.createHmac('sha256', secret);
            const signature = hmac.update(bodyString).digest('hex');

            const res = await request(app)
                .post('/api/v1/webhooks/github')
                .set('X-GitHub-Event', 'push')
                .set('X-GitHub-Delivery', deliveryId)
                .set('X-Hub-Signature-256', `sha256=${signature}`)
                .set('Content-Type', 'application/json')
                .send(bodyString);

            expect(res.status).toBe(202);
            expect(res.body.status).toBe('accepted');
            expect(res.body.pipeline_id).toBeDefined();
        });
    });
});
