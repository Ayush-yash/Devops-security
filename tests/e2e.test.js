const request = require('supertest');
const app = require('../server');
const db = require('../db');
const { processNextJob, evaluatePipelinePolicy } = require('../worker');
const crypto = require('crypto');

describe('End-to-End DevSecOps Pipeline Flow', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('E2E Success Flow: Valid Webhook -> Scan Ingestion -> Policy Pass', async () => {
        // 1. Simulate GitHub Webhook Ingest
        const secret = 'test_webhook_secret';
        const payload = {
            ref: 'refs/heads/main',
            after: 'sha992e2e',
            repository: { html_url: 'https://github.com/org/payment-gateway' },
            pusher: { name: 'developer' }
        };
        const bodyString = JSON.stringify(payload);
        const hmac = crypto.createHmac('sha256', secret);
        const signature = hmac.update(bodyString).digest('hex');

        // Setup mock database operations for webhook ingest
        db.query
            .mockResolvedValueOnce({ rows: [] }) // Idempotency check: no duplicate
            .mockResolvedValueOnce({ rows: [{ id: 'P1', name: 'payment-gateway', github_webhook_secret: secret }] }) // Get project
            .mockResolvedValueOnce({ rows: [] }) // Duplicate check pipeline: none
            .mockResolvedValueOnce({ rows: [] }) // Save processed webhook
            .mockResolvedValueOnce({ rows: [] }) // Insert pipeline run
            .mockResolvedValueOnce({ rows: [] }) // Audit log push
            .mockResolvedValueOnce({ rows: [] }); // Enqueue scan job

        const webhookRes = await request(app)
            .post('/api/v1/webhooks/github')
            .set('X-GitHub-Delivery', 'dlv-e2e-1')
            .set('X-GitHub-Event', 'push')
            .set('X-Hub-Signature-256', `sha256=${signature}`)
            .set('Content-Type', 'application/json')
            .send(bodyString);

        expect(webhookRes.status).toBe(202);
        const pipelineId = webhookRes.body.pipeline_id;
        expect(pipelineId).toBeDefined();

        // 2. Simulate Scanner Ingesting Results
        const mockPipeline = {
            id: pipelineId,
            project_id: 'P1',
            status: 'SCANNING',
            scans: {
                SAST: { name: 'Semgrep', status: 'RUNNING', progress: 50, count: 0 }
            }
        };

        // Align exactly with executed queries for SCANNING status
        db.query
            .mockResolvedValueOnce({ rows: [mockPipeline] }) // Select pipeline run (server.js)
            .mockResolvedValueOnce({ rows: [] }) // Update scans column (server.js)
            .mockResolvedValueOnce({ rows: [{ key: 'criticalBlock', value: true }] }) // Get policies (server.js)
            // evaluatePipelinePolicy begins (worker.js):
            .mockResolvedValueOnce({ rows: [{ ...mockPipeline, project: 'payment-gateway' }] }) // Select pipeline (worker.js)
            .mockResolvedValueOnce({ rows: [] }) // Select findings (worker.js, empty)
            .mockResolvedValueOnce({ rows: [{ key: 'criticalBlock', value: true }] }); // Select policies (worker.js)

        const ingestRes = await request(app)
            .post('/api/v1/ingest/scan-results')
            .send({
                pipeline_id: pipelineId,
                scanner_type: 'SAST',
                scan_status: 'PASSED',
                findings: [] // No vulnerabilities found
            });

        expect(ingestRes.status).toBe(200);
        expect(ingestRes.body.status).toBe('success');
    });

    test('E2E Block Flow: Webhook -> Scanner Ingests Critical Finding -> Policy Blocks Gate', async () => {
        const pipelineId = 'run-e2e-block';
        const mockPipeline = {
            id: pipelineId,
            project_id: 'P1',
            status: 'SCANNING',
            scans: {
                SECRETS: { name: 'Gitleaks', status: 'RUNNING', progress: 50, count: 0 }
            }
        };

        const criticalSecretFinding = {
            cve: 'SEC-SECRET-AWS_KEY',
            title: 'Plaintext AWS Access Key',
            description: 'Found AWS key in source code',
            file: 'config.js',
            line: 12,
            severity: 'CRITICAL'
        };

        // Align exactly with queries executed for SCANNING status with findings
        db.query
            .mockResolvedValueOnce({ rows: [mockPipeline] }) // Select pipeline run (server.js)
            .mockResolvedValueOnce({ rows: [] }) // Update scans column (server.js)
            .mockResolvedValueOnce({ rows: [
                { key: 'secretsBlock', value: true },
                { key: 'criticalBlock', value: true }
            ] }) // Fetch policies (server.js)
            .mockResolvedValueOnce({ rows: [] }) // Insert finding into vulnerabilities table (server.js)
            // OPA Policy Gating begins (worker.js):
            .mockResolvedValueOnce({ rows: [{ ...mockPipeline, project: 'payment-gateway' }] }) // Select pipeline
            .mockResolvedValueOnce({ rows: [
                { id: 'V1', scannerType: 'SECRETS', severity: 'CRITICAL', status: 'OPEN', active_waiver: false }
            ] }) // Select findings
            .mockResolvedValueOnce({ rows: [
                { key: 'secretsBlock', value: true },
                { key: 'criticalBlock', value: true }
            ] }) // Select policies
            .mockResolvedValueOnce({ rows: [] }) // Transition status to ANALYZING
            .mockResolvedValueOnce({ rows: [] }) // Log event: ANALYZING
            .mockResolvedValueOnce({ rows: [] }) // Transition status to POLICY_CHECK
            .mockResolvedValueOnce({ rows: [] }) // Log event: POLICY_CHECK
            .mockResolvedValueOnce({ rows: [] }) // Log blocked event
            .mockResolvedValueOnce({ rows: [] }) // Enqueue notification event
            .mockResolvedValueOnce({ rows: [] }) // Enqueue email notification
            .mockResolvedValueOnce({ rows: [] }) // Save policy_evaluations audit
            .mockResolvedValueOnce({ rows: [] }); // Update pipeline status to BLOCKED in database

        const ingestRes = await request(app)
            .post('/api/v1/ingest/scan-results')
            .send({
                pipeline_id: pipelineId,
                scanner_type: 'SECRETS',
                scan_status: 'FAILED',
                findings: [criticalSecretFinding]
            });

        expect(ingestRes.status).toBe(200);

        // Verify OPA blocking database update was fired
        const blockQuery = db.query.mock.calls.find(call => 
            call[0] && call[0].includes('UPDATE pipelines SET status = $1, completed_at = now() WHERE id = $2')
        );
        expect(blockQuery).toBeDefined();
        expect(blockQuery[1][0]).toBe('BLOCKED');
    });

    test('Failure Case: Malformed Scan Result returns 400 Bad Request', async () => {
        const res = await request(app)
            .post('/api/v1/ingest/scan-results')
            .send({
                pipeline_id: 12345, // invalid type, should be string
                scanner_type: 'SAST',
                scan_status: 'INVALID_STATUS'
            });
        expect(res.status).toBe(400);
        expect(res.body.error).toContain('Invalid request');
    });
});
