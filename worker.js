const db = require('./db');
const {
    pipelinesTotal,
    scannerDuration,
    scannerFailuresTotal,
    workerJobsTotal,
    workerFailuresTotal
} = require('./metrics');
const logger = require('./logger');

async function logPipelineEvent(pipelineId, stage, severity, message, details = {}) {
    try {
        const pipelineRes = await db.query('SELECT scans FROM pipelines WHERE id = $1', [pipelineId]);
        const correlationId = (pipelineRes.rows[0] && pipelineRes.rows[0].scans) ? pipelineRes.rows[0].scans.correlation_id : null;
        
        const mergedDetails = { ...details };
        if (correlationId) {
            mergedDetails.correlationId = correlationId;
        }

        await db.query(
            `INSERT INTO pipeline_logs (pipeline_id, stage, severity, message, details) VALUES ($1, $2, $3, $4, $5)`,
            [pipelineId, stage, severity, message, JSON.stringify(mergedDetails)]
        );
    } catch (err) {
        logger.error("Failed to log pipeline event", { pipelineId, stage, error: err.message });
    }
}

async function enqueueNotification(channel, eventType, payload) {
    try {
        await db.query(
            'INSERT INTO notification_events (channel, event_type, payload) VALUES ($1, $2, $3)',
            [channel, eventType, JSON.stringify(payload)]
        );
    } catch (err) {
        logger.error(`Failed to enqueue ${channel} notification`, { eventType, error: err.message });
    }
}

async function evaluateOPAGate(input) {
    const urls = [
        'http://shieldops-opa:8181/v1/data/devsecops/security_gate',
        'http://localhost:8181/v1/data/devsecops/security_gate'
    ];
    for (const url of urls) {
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ input })
            });
            if (response.ok) {
                const data = await response.json();
                if (data && data.result) {
                    logger.info(`Successfully evaluated policy via OPA service (${url})`);
                    return data.result;
                }
            }
        } catch (err) {
            // Try next URL
        }
    }

    // Local JS OPA/Rego Fallback Interpreter
    logger.warn("OPA servers offline or unreachable, falling back to local JS Rego engine...");
    const findings = input.findings || [];
    const config = input.config || {};

    const openFindings = findings.filter(f => f.status === 'OPEN' && !f.active_waiver);
    
    const hasSecrets = openFindings.some(f => f.scannerType === 'SECRETS');
    const hasCritical = config.criticalBlock && openFindings.some(f => f.severity === 'CRITICAL');
    const highCount = openFindings.filter(f => f.severity === 'HIGH').length;
    const mediumCount = openFindings.filter(f => f.severity === 'MEDIUM').length;
    const hasInsecureContainer = config.registryBlock && openFindings.some(f => f.scannerType === 'CONTAINER');
    const hasInsecureIaC = config.registryBlock && openFindings.some(f => f.scannerType === 'IAC');

    const blockReasons = [];
    if (hasSecrets) blockReasons.push("Exposed secrets found in code.");
    if (hasCritical) blockReasons.push("Critical vulnerabilities found.");
    if (highCount >= 3) blockReasons.push(`High vulnerability threshold exceeded (${highCount} found, limit is 3).`);
    if (hasInsecureContainer) blockReasons.push("Insecure container base image configuration found.");
    if (hasInsecureIaC) blockReasons.push("Insecure Infrastructure-as-Code configuration found.");

    const warnReasons = [];
    if (mediumCount >= 5) warnReasons.push(`Medium vulnerability threshold exceeded (${mediumCount} found, limit is 5).`);

    if (blockReasons.length > 0) {
        return {
            allow: false,
            verdict: "BLOCK",
            reason: blockReasons.join("; ")
        };
    } else if (warnReasons.length > 0) {
        return {
            allow: true,
            verdict: "WARNING",
            reason: warnReasons.join("; ")
        };
    } else {
        return {
            allow: true,
            verdict: "PASS",
            reason: "All security gates passed."
        };
    }
}

async function evaluatePipelinePolicy(pipelineId) {
    try {
        const dbPipelineRes = await db.query(
            `SELECT p.*, proj.name as project FROM pipelines p
             JOIN projects proj ON p.project_id = proj.id WHERE p.id = $1`,
            [pipelineId]
        );
        const pipeline = dbPipelineRes.rows[0];
        if (!pipeline) return;

        const findingsRes = await db.query(
            `SELECT v.id, v.scanner as "scannerType", v.severity, v.status,
             EXISTS(SELECT 1 FROM waivers w WHERE w.vulnerability_id = v.id AND w.status = 'APPROVED' AND w.expires_at > now()) as active_waiver
             FROM vulnerabilities v WHERE v.pipeline_id = $1`,
            [pipelineId]
        );
        const findings = findingsRes.rows.map(row => ({
            id: row.id,
            scannerType: row.scannerType,
            severity: row.severity,
            status: row.status,
            active_waiver: !!row.active_waiver
        }));

        const resPolicies = await db.query('SELECT key, value FROM policies');
        const policies = {};
        resPolicies.rows.forEach(row => {
            policies[row.key] = row.value;
        });

        const opaInput = {
            findings,
            config: {
                criticalBlock: !!policies.criticalBlock,
                secretsBlock: !!policies.secretsBlock,
                registryBlock: !!policies.registryBlock
            }
        };

        const decision = await evaluateOPAGate(opaInput);
        const blockPipeline = decision.verdict === "BLOCK";
        const failReason = decision.reason || "Policy violation detected.";

        let newStatus = pipeline.status;
        if (blockPipeline) {
            if (pipeline.status !== "BLOCKED") {
                if (pipeline.status === 'SCANNING') {
                    await db.query("UPDATE pipelines SET status = 'ANALYZING' WHERE id = $1", [pipelineId]);
                    await logPipelineEvent(pipelineId, 'ANALYZING', 'INFO', `Pipeline transitioned to ANALYZING`);
                    await new Promise(res => setTimeout(res, 200));
                    
                    await db.query("UPDATE pipelines SET status = 'POLICY_CHECK' WHERE id = $1", [pipelineId]);
                    await logPipelineEvent(pipelineId, 'POLICY_CHECK', 'INFO', `Pipeline transitioned to POLICY_CHECK`);
                    await new Promise(res => setTimeout(res, 200));
                }
                
                newStatus = "BLOCKED";
                await logPipelineEvent(pipelineId, 'POLICY_EVALUATION', 'ERROR', `Pipeline BLOCKED by policy`, { reason: failReason });
                
                if (policies.slackIntegration) {
                    await enqueueNotification('SLACK', 'PIPELINE_BLOCKED', { pipelineId: pipeline.id, project: pipeline.project, reason: failReason });
                }
                if (policies.jiraIntegration) {
                    await enqueueNotification('JIRA', 'PIPELINE_BLOCKED', { pipelineId: pipeline.id, project: pipeline.project, reason: failReason });
                }
                await enqueueNotification('EMAIL', 'PIPELINE_BLOCKED', { pipelineId: pipeline.id, project: pipeline.project, reason: failReason });

                let loggedKey = 'criticalBlock';
                if (failReason.toLowerCase().includes("secrets")) {
                    loggedKey = 'secretsBlock';
                } else if (failReason.toLowerCase().includes("container") || failReason.toLowerCase().includes("iac")) {
                    loggedKey = 'registryBlock';
                }

                await db.query(
                    `INSERT INTO policy_evaluations (pipeline_id, policy_key, verdict, reason)
                     VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
                    [pipeline.id, loggedKey, 'FAIL', failReason]
                );
            }
        } else {
            const scans = pipeline.scans;
            const scanKeys = Object.keys(scans);
            const allCompleted = scanKeys.every(k => scans[k].status === "PASSED" || scans[k].status === "FAILED");

            if (allCompleted && pipeline.status !== "PASSED") {
                if (pipeline.status === 'SCANNING') {
                    await db.query("UPDATE pipelines SET status = 'ANALYZING' WHERE id = $1", [pipelineId]);
                    await logPipelineEvent(pipelineId, 'ANALYZING', 'INFO', `Pipeline transitioned to ANALYZING`);
                    await new Promise(res => setTimeout(res, 200));
                    
                    await db.query("UPDATE pipelines SET status = 'POLICY_CHECK' WHERE id = $1", [pipelineId]);
                    await logPipelineEvent(pipelineId, 'POLICY_CHECK', 'INFO', `Pipeline transitioned to POLICY_CHECK`);
                    await new Promise(res => setTimeout(res, 200));
                }

                newStatus = "PASSED";
                const logVerdict = decision.verdict === "WARNING" ? "WARN" : "SUCCESS";
                await logPipelineEvent(pipelineId, 'POLICY_EVALUATION', logVerdict, `Pipeline PASSED policy checks`, { reason: failReason });

                const verdictLabel = decision.verdict === "WARNING" ? "WARN" : "PASS";
                let loggedKey = 'criticalBlock';
                if (failReason.toLowerCase().includes("secrets")) {
                    loggedKey = 'secretsBlock';
                } else if (failReason.toLowerCase().includes("container") || failReason.toLowerCase().includes("iac")) {
                    loggedKey = 'registryBlock';
                }

                await db.query(
                    `INSERT INTO policy_evaluations (pipeline_id, policy_key, verdict, reason)
                     VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
                    [pipeline.id, loggedKey, verdictLabel, failReason]
                );

                if (decision.verdict === "WARNING") {
                    await db.query(
                        `INSERT INTO alerts (type, title, desc_text)
                         VALUES ($1, $2, $3)`,
                        ['high', 'Admission Warning Triggered', `Pipeline ${pipelineId} passed with compliance warnings: ${failReason}`]
                    );
                }
            }
        }

        if (newStatus !== pipeline.status) {
            await db.query('UPDATE pipelines SET status = $1, completed_at = now() WHERE id = $2', [newStatus, pipelineId]);
        }
    } catch (err) {
        logger.error("Error evaluating policies", { pipelineId, error: err.message });
    }
}

async function simulateScanJobs(pipelineId) {
    try {
        async function transitionTo(status) {
            const isFinal = ['PASSED', 'BLOCKED', 'FAILED'].includes(status);
            if (isFinal) {
                await db.query('UPDATE pipelines SET status = $1, completed_at = now() WHERE id = $2', [status, pipelineId]);
            } else {
                await db.query('UPDATE pipelines SET status = $1 WHERE id = $2', [status, pipelineId]);
            }
            await logPipelineEvent(pipelineId, status, 'INFO', `Pipeline stage changed to ${status}`);
            
            // Track status transitions
            pipelinesTotal.inc({ status: status.toLowerCase() });
        }

        await transitionTo('CLONING');
        await new Promise(resolve => setTimeout(resolve, 1000));

        await transitionTo('SCANNING');

        const steps = ["SAST", "SCA", "SECRETS", "CONTAINER", "IAC", "DAST"];
        for (const step of steps) {
            const scanStart = process.hrtime();
            let res = await db.query('SELECT * FROM pipelines WHERE id = $1', [pipelineId]);
            let pipeline = res.rows[0];
            if (!pipeline) return;

            pipeline.scans[step].status = "RUNNING";
            pipeline.scans[step].progress = 50;
            await db.query('UPDATE pipelines SET scans = $1 WHERE id = $2', [pipeline.scans, pipelineId]);
            await logPipelineEvent(pipelineId, step, 'INFO', `Started ${pipeline.scans[step].name} scan for ${step}...`, { progress: 50 });

            await new Promise(resolve => setTimeout(resolve, 800));

            res = await db.query('SELECT p.*, proj.name as project FROM pipelines p JOIN projects proj ON p.project_id = proj.id WHERE p.id = $1', [pipelineId]);
            pipeline = res.rows[0];
            if (!pipeline) return;

            pipeline.scans[step].progress = 100;

            const resPolicies = await db.query('SELECT key, value FROM policies');
            const policies = {};
            resPolicies.rows.forEach(row => {
                policies[row.key] = row.value;
            });

            let isFailed = false;
            let findings = [];

            if (step === "SECRETS" && Math.random() > 0.5 && policies.secretsBlock) {
                isFailed = true;
                findings.push({
                    cve: "SEC-LEAK-992",
                    title: "Plaintext Token Discovered in Config",
                    description: "High entropy AWS Session Key or Slack API token detected in configuration files.",
                    file: "secrets.properties",
                    line: 5,
                    severity: "CRITICAL",
                    remediation: "Revoke token key and integrate AWS KMS Secrets provider.",
                    package: "Configuration Properties",
                    version: "1.0",
                    fixedVersion: "KMS Config"
                });
            } else if (step === "IAC" && Math.random() > 0.6 && policies.criticalBlock) {
                isFailed = true;
                findings.push({
                    cve: "IAC-OPEN-SSH",
                    title: "Public SSH Port Exposed to Internet",
                    description: "Security Group rule permits SSH traffic on port 22 from the public internet (0.0.0.0/0).",
                    file: "main.tf",
                    line: 14,
                    severity: "CRITICAL",
                    remediation: "Restrict security group ingress block CIDR to specific office VPN or bastion subnet IP ranges.",
                    package: "Terraform Security Group",
                    version: "1.0",
                    fixedVersion: "Restricted CIDR"
                });
            } else if (step === "CONTAINER" && Math.random() > 0.6 && policies.criticalBlock) {
                isFailed = true;
                findings.push({
                    cve: "CVE-2023-38545",
                    title: "LibSSL Container Execution Overflow",
                    description: "Critical buffer overflow in parsing library identified in active Docker runtime packages.",
                    file: "Dockerfile",
                    line: 2,
                    severity: "CRITICAL",
                    remediation: "Rebuild docker layers on alpine:3.18.5 base tag.",
                    package: "libssl-dev",
                    version: "3.0.4",
                    fixedVersion: "3.0.8"
                });
            } else if (step === "DAST" && Math.random() > 0.7 && policies.criticalBlock) {
                isFailed = true;
                findings.push({
                    cve: "CVE-2023-3824",
                    title: "SQL Injection on Auth Endpoint",
                    description: "OWASP ZAP dynamic fuzzer identified SQL Injection vulnerability in username forms parameter.",
                    file: "controllers/auth.js",
                    line: 124,
                    severity: "CRITICAL",
                    remediation: "Use parameterized queries or ORM frameworks instead of string concatenation.",
                    package: "Auth Controller",
                    version: "1.0",
                    fixedVersion: "Parameterized Query"
                });
            }

            if (isFailed) {
                pipeline.scans[step].status = "FAILED";
                pipeline.scans[step].count = findings.length;
                
                await logPipelineEvent(pipelineId, step, 'ERROR', `Scanner ${pipeline.scans[step].name} failed with ${findings.length} findings`, { count: findings.length });

                for (const f of findings) {
                    const vulnId = "VULN-" + Math.floor(Math.random() * 1000 + 100);
                    
                    let isBlocking = false;
                    if (step === "SECRETS" && policies.secretsBlock) {
                        isBlocking = true;
                    } else if (policies.criticalBlock && (f.severity === 'CRITICAL' || f.severity === 'HIGH')) {
                        isBlocking = true;
                    }

                    await db.query(
                        `INSERT INTO vulnerabilities (id, cve, title, description, scanner, scanner_name, project_id, file_path, line_number, severity, status, remediation, package_name, package_version, fixed_version, pipeline_id, rule_id, is_blocking)
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
                         ON CONFLICT ON CONSTRAINT unique_pipeline_finding DO NOTHING`,
                        [
                            vulnId, f.cve, f.title, f.description, step, pipeline.scans[step].name,
                            pipeline.project_id, f.file, f.line, f.severity, 'OPEN', f.remediation,
                            f.package, f.version, f.fixedVersion, pipelineId, f.cve, isBlocking
                        ]
                    );
                    await logPipelineEvent(pipelineId, step, 'WARN', `Detected vulnerability: ${f.title} (${f.cve})`, { severity: f.severity, file: f.file });
                    
                    if (f.severity === 'CRITICAL') {
                        await enqueueNotification('SLACK', 'CRITICAL_FINDING', { pipelineId, cve: f.cve, title: f.title });
                        await enqueueNotification('JIRA', 'CRITICAL_FINDING', { pipelineId, cve: f.cve, title: f.title });
                        await enqueueNotification('EMAIL', 'CRITICAL_FINDING', { pipelineId, cve: f.cve, title: f.title });
                    }
                }

                await db.query(
                    `INSERT INTO alerts (type, title, desc_text)
                     VALUES ($1, $2, $3)`,
                    ['crit', 'Gating Threshold Triggered', `Pipeline ${pipelineId} blocked by ${pipeline.scans[step].name}.`]
                );
            } else {
                pipeline.scans[step].status = "PASSED";
                await logPipelineEvent(pipelineId, step, 'SUCCESS', `Scanner ${pipeline.scans[step].name} passed successfully.`);
            }

            const scanDiff = process.hrtime(scanStart);
            const scanDurationSeconds = scanDiff[0] + scanDiff[1] / 1e9;
            scannerDuration.observe({ scanner_type: step }, scanDurationSeconds);
            if (isFailed) {
                scannerFailuresTotal.inc({ scanner_type: step });
            }

            await db.query('UPDATE pipelines SET scans = $1 WHERE id = $2', [pipeline.scans, pipelineId]);
            await new Promise(resolve => setTimeout(resolve, 400));
        }

        await transitionTo('ANALYZING');
        await new Promise(resolve => setTimeout(resolve, 1000));

        await transitionTo('POLICY_CHECK');
        await new Promise(resolve => setTimeout(resolve, 1000));

        await evaluatePipelinePolicy(pipelineId);

    } catch (err) {
        logger.error(`Failure encountered in pipeline ${pipelineId}`, { error: err.message });
        try {
            await db.query('UPDATE pipelines SET status = $1, completed_at = now() WHERE id = $2', ['FAILED', pipelineId]);
            await logPipelineEvent(pipelineId, 'FAILED', 'INFO', `Pipeline stage changed to FAILED`);
            
            await enqueueNotification('SLACK', 'PIPELINE_FAILED', { pipelineId: pipelineId, reason: err.message });
            await enqueueNotification('JIRA', 'PIPELINE_FAILED', { pipelineId: pipelineId, reason: err.message });
            await enqueueNotification('EMAIL', 'PIPELINE_FAILED', { pipelineId: pipelineId, reason: err.message });

            await db.query(
                `INSERT INTO alerts (type, title, desc_text)
                 VALUES ($1, $2, $3)`,
                ['crit', 'Pipeline Execution Failed', `Orchestrator encountered error on run ${pipelineId}: ${err.message}`]
            );
        } catch (innerErr) {
            logger.error("Critical double-fault in pipeline failure recovery handler", { error: innerErr.message });
        }
        throw err;
    }
}

let isShuttingDown = false;

async function processNextJob() {
    if (isShuttingDown) return;

    try {
        // Enforce exponential backoff retries: POWER(2, retry_count) * 5 seconds
        const { rows } = await db.query(`
            UPDATE scan_jobs
            SET status = 'RUNNING', updated_at = now()
            WHERE id = (
                SELECT id FROM scan_jobs
                WHERE status IN ('PENDING', 'FAILED') 
                  AND retry_count < 3
                  AND (status = 'PENDING' OR updated_at < NOW() - (POWER(2, retry_count) * INTERVAL '5 seconds'))
                ORDER BY created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            RETURNING id, pipeline_id, retry_count
        `);

        if (rows.length === 0) {
            return;
        }

        const job = rows[0];
        logger.info(`Picked up job ${job.id} for pipeline ${job.pipeline_id} (Attempt: ${job.retry_count + 1})`);

        try {
            await simulateScanJobs(job.pipeline_id);

            await db.query(`
                UPDATE scan_jobs 
                SET status = 'COMPLETED', updated_at = now() 
                WHERE id = $1
            `, [job.id]);
            
            logger.info(`Successfully completed job ${job.id}`);
            workerJobsTotal.inc({ job_type: 'scan', status: 'success' });
        } catch (err) {
            logger.error(`Job ${job.id} failed`, { error: err.message });
            await db.query(`
                UPDATE scan_jobs 
                SET status = 'FAILED', error_msg = $1, retry_count = retry_count + 1, updated_at = now() 
                WHERE id = $2
            `, [err.message, job.id]);
            workerJobsTotal.inc({ job_type: 'scan', status: 'failed' });
            workerFailuresTotal.inc({ job_type: 'scan' });
        }
    } catch (err) {
        logger.error("Error processing jobs", { error: err.message });
    }
}

async function startWorker() {
    logger.info("Scanner Worker Service initialized.");
    
    // Ensure DB is initialized
    await db.initDatabase();

    const pollInterval = setInterval(async () => {
        await processNextJob();
    }, 2000);

    // Graceful Shutdown
    process.on('SIGINT', () => shutdown(pollInterval));
    process.on('SIGTERM', () => shutdown(pollInterval));
}

function shutdown(interval) {
    logger.info("Worker shutting down gracefully...");
    isShuttingDown = true;
    clearInterval(interval);
    setTimeout(async () => {
        try {
            await db.pool.end();
            logger.info("Worker database pool closed. Exited.");
            process.exit(0);
        } catch (err) {
            logger.error("Worker error during DB pool shutdown", { error: err.message });
            process.exit(1);
        }
    }, 1000);
}

if (require.main === module) {
    startWorker();
}

module.exports = {
    startWorker,
    processNextJob,
    simulateScanJobs,
    evaluatePipelinePolicy,
    evaluateOPAGate
};
