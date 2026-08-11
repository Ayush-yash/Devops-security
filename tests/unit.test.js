const { evaluateOPAGate } = require('../worker');
const logger = require('../logger');

describe('Unit Tests: OPA Gate Policy Engine', () => {
    test('CRITICAL vulnerability blocks the pipeline when criticalBlock policy is active', async () => {
        const input = {
            findings: [
                { id: 'V1', scannerType: 'SCA', severity: 'CRITICAL', status: 'OPEN', active_waiver: false }
            ],
            config: {
                criticalBlock: true,
                secretsBlock: false,
                registryBlock: false
            }
        };
        const decision = await evaluateOPAGate(input);
        expect(decision.allow).toBe(false);
        expect(decision.verdict).toBe('BLOCK');
        expect(decision.reason).toContain('Critical vulnerabilities found');
    });

    test('Exposed secret in code blocks the pipeline unconditionally', async () => {
        const input = {
            findings: [
                { id: 'V2', scannerType: 'SECRETS', severity: 'HIGH', status: 'OPEN', active_waiver: false }
            ],
            config: {
                criticalBlock: false,
                secretsBlock: true,
                registryBlock: false
            }
        };
        const decision = await evaluateOPAGate(input);
        expect(decision.allow).toBe(false);
        expect(decision.verdict).toBe('BLOCK');
        expect(decision.reason).toContain('Exposed secrets found in code');
    });

    test('3 or more HIGH vulnerabilities blocks the pipeline', async () => {
        const input = {
            findings: [
                { id: 'V1', scannerType: 'SCA', severity: 'HIGH', status: 'OPEN', active_waiver: false },
                { id: 'V2', scannerType: 'SAST', severity: 'HIGH', status: 'OPEN', active_waiver: false },
                { id: 'V3', scannerType: 'IAC', severity: 'HIGH', status: 'OPEN', active_waiver: false }
            ],
            config: {
                criticalBlock: false,
                secretsBlock: false,
                registryBlock: false
            }
        };
        const decision = await evaluateOPAGate(input);
        expect(decision.allow).toBe(false);
        expect(decision.verdict).toBe('BLOCK');
        expect(decision.reason).toContain('High vulnerability threshold exceeded');
    });

    test('Pipeline passes when findings are below threshold', async () => {
        const input = {
            findings: [
                { id: 'V1', scannerType: 'SCA', severity: 'MEDIUM', status: 'OPEN', active_waiver: false }
            ],
            config: {
                criticalBlock: true,
                secretsBlock: true,
                registryBlock: true
            }
        };
        const decision = await evaluateOPAGate(input);
        expect(decision.allow).toBe(true);
        expect(decision.verdict).toBe('PASS');
    });

    test('Waiver correctly bypasses blocked critical vulnerability', async () => {
        const input = {
            findings: [
                { id: 'V1', scannerType: 'SCA', severity: 'CRITICAL', status: 'OPEN', active_waiver: true }
            ],
            config: {
                criticalBlock: true,
                secretsBlock: true,
                registryBlock: true
            }
        };
        const decision = await evaluateOPAGate(input);
        expect(decision.allow).toBe(true);
        expect(decision.verdict).toBe('PASS');
    });
});

describe('Unit Tests: Structured JSON Logger', () => {
    test('Logger outputs valid structured JSON logs', () => {
        logger.silent = false;
        const originalLog = console.log;
        let loggedText = null;
        console.log = (msg) => { loggedText = msg; };

        logger.info('User action logged', { userId: 42 });

        console.log = originalLog;
        logger.silent = true;

        expect(loggedText).not.toBeNull();
        const logData = JSON.parse(loggedText);
        expect(logData.level).toBe('INFO');
        expect(logData.message).toBe('User action logged');
        expect(logData.userId).toBe(42);
        expect(logData.timestamp).toBeDefined();
    });

    test('Logger formats AggregateError array messages correctly', () => {
        logger.silent = false;
        const originalError = console.error;
        let loggedText = null;
        console.error = (msg) => { loggedText = msg; };

        const mockError = new Error('Sub-error connection failed');
        const aggregateError = new Error('Main Connection Error');
        aggregateError.errors = [mockError];

        logger.error('Database connection timed out', { error: aggregateError });

        console.error = originalError;
        logger.silent = true;

        expect(loggedText).not.toBeNull();
        const logData = JSON.parse(loggedText);
        expect(logData.level).toBe('ERROR');
        expect(logData.error).toContain('Sub-error connection failed');
    });
});
