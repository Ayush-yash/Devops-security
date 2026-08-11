const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const crypto = require('crypto');
const db = require('./db');
const EventEmitter = require('events');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const logger = require('./logger');
const { evaluatePipelinePolicy } = require('./worker');

const pipelineEvents = new EventEmitter();
// Increase max listeners if many concurrent pipelines are viewed
pipelineEvents.setMaxListeners(100);

async function logPipelineEvent(pipelineId, stage, severity, message, details = {}) {
    try {
        await db.query(
            `INSERT INTO pipeline_logs (pipeline_id, stage, severity, message, details) VALUES ($1, $2, $3, $4, $5)`,
            [pipelineId, stage, severity, message, JSON.stringify(details)]
        );
    } catch (err) {
        logger.error("Failed to log pipeline event", { pipelineId, error: err.message });
    }
}

// -------------------------------------------------------------
// PostgreSQL Event Listener for Pipeline Logs
// -------------------------------------------------------------
async function setupDatabaseListener() {
    const { Client } = require('pg');
    const client = new Client({
        connectionString: process.env.DATABASE_URL || 'postgres://shieldops:securepassword@localhost:5432/shieldops'
    });
    try {
        await client.connect();
        client.on('notification', (msg) => {
            if (msg.channel === 'pipeline_logs_channel') {
                const logEntry = JSON.parse(msg.payload);
                pipelineEvents.emit(`log-${logEntry.pipeline_id}`, logEntry);
            }
        });
        await client.query('LISTEN pipeline_logs_channel');
        logger.info("Listening for pipeline logs from PostgreSQL...");
    } catch (err) {
        logger.error("Failed to setup DB listener", { error: err });
    }
}
setupDatabaseListener();

// -------------------------------------------------------------
// Notification Service
// -------------------------------------------------------------
async function enqueueNotification(channel, eventType, payload) {
    try {
        await db.query(
            `INSERT INTO notification_events (channel, event_type, payload) VALUES ($1, $2, $3)`,
            [channel, eventType, JSON.stringify(payload)]
        );
    } catch (err) {
        logger.error(`Failed to enqueue ${channel} notification`, { eventType, error: err.message });
    }
}

// Background Worker to process notifications
let notificationInterval;
if (process.env.NODE_ENV !== 'test') {
    notificationInterval = setInterval(async () => {
        try {
            const res = await db.query(
                `SELECT * FROM notification_events 
                 WHERE status IN ('PENDING', 'FAILED') AND retry_count < 3
                 ORDER BY created_at ASC LIMIT 10`
            );
            
            for (const notif of res.rows) {
                let success = false;
                let errorMsg = null;
                
                // Check credentials and execute delivery attempts
                if (notif.channel === 'SLACK') {
                    if (!process.env.SLACK_WEBHOOK_URL) {
                        errorMsg = "Credentials absent";
                    } else {
                        try {
                            const response = await fetch(process.env.SLACK_WEBHOOK_URL, {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({
                                    text: `[ShieldOps Alert] ${notif.event_type}\nPayload: ${JSON.stringify(notif.payload, null, 2)}`
                                })
                            });
                            if (response.ok) {
                                success = true;
                            } else {
                                errorMsg = `Slack API returned status ${response.status}`;
                            }
                        } catch (err) {
                            errorMsg = `Slack delivery failed: ${err.message}`;
                        }
                    }
                } else if (notif.channel === 'JIRA') {
                    if (!process.env.JIRA_API_TOKEN || !process.env.JIRA_BASE_URL || !process.env.JIRA_PROJECT_KEY) {
                        errorMsg = "Credentials absent";
                    } else {
                        try {
                            const response = await fetch(`${process.env.JIRA_BASE_URL}/rest/api/2/issue`, {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                    'Authorization': `Bearer ${process.env.JIRA_API_TOKEN}`
                                },
                                body: JSON.stringify({
                                    fields: {
                                        project: { key: process.env.JIRA_PROJECT_KEY },
                                        summary: `[ShieldOps Alert] ${notif.event_type}`,
                                        description: `Event Details:\n${JSON.stringify(notif.payload, null, 2)}`,
                                        issuetype: { name: 'Bug' }
                                    }
                                })
                            });
                            if (response.ok) {
                                success = true;
                            } else {
                                errorMsg = `Jira API returned status ${response.status}`;
                            }
                        } catch (err) {
                            errorMsg = `Jira delivery failed: ${err.message}`;
                        }
                    }
                } else if (notif.channel === 'EMAIL') {
                    if (!process.env.EMAIL_SMTP_HOST || !process.env.EMAIL_TO) {
                        errorMsg = "Credentials absent";
                    } else {
                        try {
                            const nodemailer = require('nodemailer');
                            const transporter = nodemailer.createTransport({
                                host: process.env.EMAIL_SMTP_HOST,
                                port: parseInt(process.env.EMAIL_SMTP_PORT) || 587,
                                secure: process.env.EMAIL_SMTP_SECURE === 'true',
                                auth: process.env.EMAIL_SMTP_USER ? {
                                    user: process.env.EMAIL_SMTP_USER,
                                    pass: process.env.EMAIL_SMTP_PASS
                                } : undefined
                            });
                            await transporter.sendMail({
                                from: process.env.EMAIL_FROM || 'no-reply@shieldops.internal',
                                to: process.env.EMAIL_TO,
                                subject: `[ShieldOps Alert] ${notif.event_type}`,
                                text: `Alert details:\n${JSON.stringify(notif.payload, null, 2)}`
                            });
                            success = true;
                        } catch (err) {
                            errorMsg = `Email delivery failed: ${err.message}`;
                        }
                    }
                }
                
                if (success) {
                    await db.query(`UPDATE notification_events SET status = 'SENT', updated_at = now() WHERE id = $1`, [notif.id]);
                    logger.info(`Successfully sent ${notif.channel} notification for event ${notif.event_type}`);
                } else {
                    await db.query(`UPDATE notification_events SET status = 'FAILED', error_msg = $1, retry_count = retry_count + 1, updated_at = now() WHERE id = $2`, [errorMsg, notif.id]);
                    logger.warn(`Failed to send ${notif.channel} notification (Attempt ${notif.retry_count + 1}): ${errorMsg}`);
                }
            }
        } catch (err) {
            logger.error("Error in notification worker loop", { error: err });
        }
    }, 5000);
}

const app = express();
const PORT = process.env.PORT || 8080;

const {
    register,
    httpRequestsTotal,
    httpRequestDuration,
    apiErrorsTotal,
    pipelinesTotal,
    securityFindingsTotal
} = require('./metrics');

// Request Correlation ID & Prometheus tracking middleware
app.use((req, res, next) => {
    const correlationId = req.headers['x-correlation-id'] || crypto.randomUUID();
    req.correlationId = correlationId;
    res.setHeader('X-Correlation-ID', correlationId);

    const start = process.hrtime();

    res.on('finish', () => {
        const diff = process.hrtime(start);
        const durationSeconds = diff[0] + diff[1] / 1e9;
        const route = req.route ? req.route.path : req.path;
        const statusStr = String(res.statusCode);

        // Record HTTP metrics
        httpRequestsTotal.inc({ method: req.method, route, status: statusStr });
        httpRequestDuration.observe({ method: req.method, route, status: statusStr }, durationSeconds);

        if (res.statusCode >= 400) {
            apiErrorsTotal.inc({ route, error_type: res.statusCode >= 500 ? 'SERVER_ERROR' : 'CLIENT_ERROR' });
        }
    });

    next();
});

// Prometheus Metrics Endpoint
app.get('/metrics', async (req, res) => {
    try {
        // Dynamically update active findings gauge upon scrape
        const findingsCountRes = await db.query(
            `SELECT severity, scanner, COUNT(*) as count 
             FROM vulnerabilities 
             WHERE status = 'OPEN' 
             GROUP BY severity, scanner`
        );
        securityFindingsTotal.reset();
        for (const row of findingsCountRes.rows) {
            securityFindingsTotal.set({ severity: row.severity, scanner: row.scanner }, parseInt(row.count));
        }

        res.set('Content-Type', register.contentType);
        res.end(await register.metrics());
    } catch (err) {
        res.status(500).end(err);
    }
});

// Apply Helmet Security Headers with dynamic CSP policies
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'", "http://localhost:8080", "ws://localhost:8080"]
        }
    }
}));

// Strict CORS Policy Configuration
const corsOptions = {
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
            'http://localhost:8080',
            'http://127.0.0.1:8080'
        ];
        
        if (process.env.CORS_ALLOWED_ORIGINS) {
            allowedOrigins.push(...process.env.CORS_ALLOWED_ORIGINS.split(','));
        }
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
};
app.use(cors(corsOptions));

// API Rate Limiting to prevent brute-forcing and abuse
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many requests from this IP, please try again after 15 minutes." }
});
app.use('/api/', apiLimiter);

// Configure body-parser to preserve raw body for Webhook Verification
app.use(bodyParser.json({
    verify: (req, res, buf) => {
        req.rawBody = buf;
    }
}));

// Serve static dashboard files from the current folder
app.use(express.static(__dirname));

// -------------------------------------------------------------
// Helper: format relative time for UI compatibility
// -------------------------------------------------------------
function timeAgo(date) {
    const seconds = Math.floor((new Date() - new Date(date)) / 1000);
    if (seconds < 60) return "Just now";
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes} mins ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours} hours ago`;
    const days = Math.floor(hours / 24);
    return `${days} days ago`;
}

// -------------------------------------------------------------
// RBAC Middleware: Enforce Permissions on Backend APIs
// -------------------------------------------------------------
function requireRole(allowedRoles) {
    return (req, res, next) => {
        const userRole = req.headers['x-user-role'];
        if (!userRole) {
            return res.status(401).json({ error: "Unauthorized: Missing X-User-Role header" });
        }
        if (!allowedRoles.includes(userRole.toUpperCase())) {
            return res.status(403).json({ error: `Forbidden: Role '${userRole}' does not have permission for this action` });
        }
        next();
    };
}

// -------------------------------------------------------------
// REST API Routes
// -------------------------------------------------------------

// Integrations Config Status Check
app.get('/api/v1/integrations/status', (req, res) => {
    res.json({
        slack: { configured: !!process.env.SLACK_WEBHOOK_URL },
        jira: { configured: !!process.env.JIRA_API_TOKEN },
        email: { configured: !!process.env.EMAIL_SMTP_HOST }
    });
});

// Liveness check
app.get('/health', (req, res) => {
    res.status(200).json({ status: "UP", timestamp: new Date() });
});

app.get('/api/v1/health', async (req, res) => {
    try {
        await db.query('SELECT 1');
        res.json({ status: "UP", database: "CONNECTED" });
    } catch (err) {
        logger.error("Health check failed", { error: err.message });
        res.status(500).json({ status: "DOWN", database: "DISCONNECTED" });
    }
});

// Readiness check
app.get('/ready', async (req, res) => {
    try {
        await db.query('SELECT 1');
        res.status(200).json({ status: "READY" });
    } catch (err) {
        logger.error("Readiness check failed", { error: err.message });
        res.status(503).json({ status: "NOT_READY" });
    }
});

// 1. Unified Findings List API with dynamic filters
app.get('/api/v1/findings', requireRole(['ADMIN', 'SECURITY_LEAD', 'DEVELOPER']), async (req, res) => {
    const { severity, scanner, status } = req.query;
    try {
        let queryText = `
            SELECT v.id, v.cve, v.title, v.description, v.scanner, v.scanner_name as "scannerName",
                   p.name as project, v.file_path as "filePath", v.file_path as file, v.line_number as "lineNumber", v.line_number as line, v.severity,
                   CASE 
                     WHEN w.status = 'APPROVED' AND w.expires_at > now() THEN 'WAIVED'
                     ELSE v.status 
                   END as status,
                   v.remediation, v.package_name as package, v.package_version as version,
                   v.fixed_version as "fixedVersion", v.pipeline_id as "pipelineId", v.created_at as "createdAt",
                   v.rule_id as "ruleId", v.is_blocking as "isBlocking",
                   w.status as "waiverStatus", w.reason as "waiverReason", w.requester_email as "waiverRequester",
                   w.approver_email as "waiverApprover", w.expires_at as "waiverExpiresAt"
            FROM vulnerabilities v
            JOIN projects p ON v.project_id = p.id
            LEFT JOIN LATERAL (
                SELECT * FROM waivers 
                WHERE vulnerability_id = v.id 
                ORDER BY created_at DESC LIMIT 1
            ) w ON TRUE
        `;
        const conditions = [];
        const params = [];
        
        if (severity) {
            params.push(severity.toUpperCase());
            conditions.push(`v.severity = $${params.length}`);
        }
        if (scanner) {
            params.push(scanner.toUpperCase());
            conditions.push(`v.scanner = $${params.length}`);
        }
        if (status) {
            const targetStatus = status.toUpperCase();
            if (targetStatus === 'WAIVED') {
                conditions.push(`w.status = 'APPROVED' AND w.expires_at > now()`);
            } else if (targetStatus === 'OPEN') {
                conditions.push(`v.status = 'OPEN' AND (w.status IS NULL OR w.status != 'APPROVED' OR w.expires_at <= now())`);
            } else {
                params.push(targetStatus);
                conditions.push(`v.status = $${params.length}`);
            }
        }
        
        if (conditions.length > 0) {
            queryText += " WHERE " + conditions.join(" AND ");
        }
        
        queryText += " ORDER BY v.created_at DESC;";
        
        const result = await db.query(queryText, params);
        res.json(result.rows);
    } catch (err) {
        console.error("Error fetching findings:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get('/api/v1/dashboard/stats', async (req, res) => {
    try {
        const projRes = await db.query('SELECT COUNT(*) FROM projects');
        const totalProjects = parseInt(projRes.rows[0].count);

        const pipeRes = await db.query('SELECT status, COUNT(*) FROM pipelines GROUP BY status');
        let totalPipelines = 0, passedPipelines = 0, failedPipelines = 0, blockedPipelines = 0;
        pipeRes.rows.forEach(row => {
            const count = parseInt(row.count);
            totalPipelines += count;
            if (row.status === 'PASSED') passedPipelines += count;
            if (row.status === 'FAILED') failedPipelines += count;
            if (row.status === 'BLOCKED') blockedPipelines += count;
        });

        const vulnRes = await db.query('SELECT severity, status, COUNT(*) FROM vulnerabilities GROUP BY severity, status');
        let criticalFindings = 0, highFindings = 0, mediumFindings = 0, lowFindings = 0, openFindings = 0;
        vulnRes.rows.forEach(row => {
            const count = parseInt(row.count);
            if (row.status === 'OPEN') {
                openFindings += count;
                if (row.severity === 'CRITICAL') criticalFindings += count;
                if (row.severity === 'HIGH') highFindings += count;
                if (row.severity === 'MEDIUM') mediumFindings += count;
                if (row.severity === 'LOW') lowFindings += count;
            }
        });

        const scanDistRes = await db.query("SELECT scanner as name, COUNT(*) as value FROM vulnerabilities WHERE status = 'OPEN' GROUP BY scanner");
        const scannerDistribution = scanDistRes.rows.map(row => ({ name: row.name, value: parseInt(row.value) }));

        // Dynamically compute monthly trends for the last 6 months from real data
        const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        const currentMonthIdx = new Date().getMonth();
        const activeMonths = [];
        for (let i = 5; i >= 0; i--) {
            let m = currentMonthIdx - i;
            if (m < 0) m += 12;
            activeMonths.push(months[m]);
        }
        
        const trends = {
            labels: activeMonths,
            datasets: {
                critical: new Array(6).fill(0),
                high: new Array(6).fill(0),
                medium: new Array(6).fill(0)
            }
        };

        const trendRes = await db.query(`
            SELECT 
                TO_CHAR(created_at, 'Mon') as month,
                COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) as critical,
                COUNT(CASE WHEN severity = 'HIGH' THEN 1 END) as high,
                COUNT(CASE WHEN severity = 'MEDIUM' THEN 1 END) as medium
            FROM vulnerabilities
            WHERE created_at >= NOW() - INTERVAL '6 months'
            GROUP BY TO_CHAR(created_at, 'Mon')
        `);

        trendRes.rows.forEach(row => {
            const idx = activeMonths.indexOf(row.month);
            if (idx !== -1) {
                trends.datasets.critical[idx] = parseInt(row.critical);
                trends.datasets.high[idx] = parseInt(row.high);
                trends.datasets.medium[idx] = parseInt(row.medium);
            }
        });

        let healthScore = 100 - (criticalFindings * 10) - (highFindings * 5) - (mediumFindings * 2);
        if (healthScore < 0) healthScore = 0;
        if (healthScore > 100) healthScore = 100;

        const recentRes = await db.query(`
            SELECT pip.id, proj.name as project, pip.ci_system as "ciSystem", pip.branch,
                   pip.commit_sha as commit, pip.trigger_event as "trigger", pip.status, pip.scans
            FROM pipelines pip
            JOIN projects proj ON pip.project_id = proj.id
            ORDER BY pip.created_at DESC LIMIT 5
        `);

        res.json({
            metrics: {
                projects: totalProjects,
                pipelines: { total: totalPipelines, passed: passedPipelines, failed: failedPipelines, blocked: blockedPipelines },
                findings: { critical: criticalFindings, high: highFindings, medium: mediumFindings, low: lowFindings, open: openFindings }
            },
            healthScore,
            trends,
            scannerDistribution,
            recentPipelines: recentRes.rows
        });
    } catch (err) {
        console.error("Error fetching dashboard stats:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get('/api/v1/pipelines', async (req, res) => {
    try {
        const queryText = `
            SELECT pip.id, proj.name as project, pip.ci_system as "ciSystem", pip.branch,
                   pip.commit_sha as commit, pip.trigger_event as "trigger", pip.status, pip.scans
            FROM pipelines pip
            JOIN projects proj ON pip.project_id = proj.id
            ORDER BY pip.created_at DESC;
        `;
        const result = await db.query(queryText);
        res.json(result.rows);
    } catch (err) {
        console.error("Error fetching pipelines:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get('/api/v1/alerts', async (req, res) => {
    try {
        const result = await db.query('SELECT id, type, title, desc_text as desc, created_at FROM alerts ORDER BY created_at DESC');
        const formattedAlerts = result.rows.map(row => ({
            id: Number(row.id),
            type: row.type,
            title: row.title,
            desc: row.desc,
            time: timeAgo(row.created_at)
        }));
        res.json(formattedAlerts);
    } catch (err) {
        console.error("Error fetching alerts:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// 2. Policy Settings Management - Enforced RBAC (ADMIN, SECURITY_LEAD)
app.get('/api/v1/policies', async (req, res) => {
    try {
        const result = await db.query('SELECT key, value FROM policies');
        const policies = {};
        result.rows.forEach(row => {
            policies[row.key] = row.value;
        });
        res.json(policies);
    } catch (err) {
        console.error("Error fetching policies:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.post('/api/v1/policies', requireRole(['ADMIN', 'SECURITY_LEAD']), async (req, res) => {
    const userRole = req.headers['x-user-role'] || 'SECURITY_LEAD';
    const actorName = userRole === 'SECURITY_LEAD' ? 'Jane Doe' : (userRole === 'ADMIN' ? 'Admin User' : 'Dave Dev');
    
    try {
        const keys = Object.keys(req.body);
        for (const key of keys) {
            const value = req.body[key];
            await db.query(
                `INSERT INTO policies (key, value) VALUES ($1, $2)
                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
                [key, value]
            );
        }

        // Log audit
        await db.query(
            `INSERT INTO audit_logs (actor, role, action, outcome, details)
             VALUES ($1, $2, $3, $4, $5)`,
            [actorName, userRole, 'policy.update', 'SUCCESS', JSON.stringify(req.body)]
        );

        // Fetch and return updated policies
        const result = await db.query('SELECT key, value FROM policies');
        const policies = {};
        result.rows.forEach(row => {
            policies[row.key] = row.value;
        });
        res.json({ status: "success", policies });
    } catch (err) {
        console.error("Error updating policies:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// 3. Vulnerability Status Actions - Enforced RBAC
app.post('/api/v1/remediate/:id', requireRole(['ADMIN', 'SECURITY_LEAD', 'DEVELOPER']), async (req, res) => {
    const userRole = req.headers['x-user-role'] || 'SECURITY_LEAD';
    const actorName = userRole === 'SECURITY_LEAD' ? 'Jane Doe' : (userRole === 'ADMIN' ? 'Admin User' : 'Dave Dev');

    try {
        const vulnRes = await db.query(
            `SELECT v.*, p.name as project FROM vulnerabilities v
             JOIN projects p ON v.project_id = p.id WHERE v.id = $1`,
            [req.params.id]
        );
        const vuln = vulnRes.rows[0];

        if (vuln) {
            await db.query('UPDATE vulnerabilities SET status = $1 WHERE id = $2', ['RESOLVED', req.params.id]);

            const desc = `Auto-patch applied for ${vuln.cve} in '${vuln.project}'.`;
            await db.query(
                'INSERT INTO alerts (type, title, desc_text) VALUES ($1, $2, $3)',
                ['info', 'Remediation Applied', desc]
            );

            // Audit logging
            await db.query(
                `INSERT INTO audit_logs (actor, role, action, outcome, details)
                 VALUES ($1, $2, $3, $4, $5)`,
                [actorName, userRole, 'vulnerability.remediate', 'SUCCESS', JSON.stringify({ vuln_id: req.params.id, cve: vuln.cve, project: vuln.project })]
            );

            res.json({ status: "success", vuln: { ...vuln, status: 'RESOLVED' } });
        } else {
            res.status(404).json({ error: "Vulnerability not found" });
        }
    } catch (err) {
        console.error("Error in remediate:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Reopen Finding (ADMIN, SECURITY_LEAD, DEVELOPER)
app.post('/api/v1/findings/:id/reopen', requireRole(['ADMIN', 'SECURITY_LEAD', 'DEVELOPER']), async (req, res) => {
    const userRole = req.headers['x-user-role'] || 'SECURITY_LEAD';
    const actorName = userRole === 'SECURITY_LEAD' ? 'Jane Doe' : (userRole === 'ADMIN' ? 'Admin User' : 'Dave Dev');

    try {
        const vulnRes = await db.query(
            `SELECT v.*, p.name as project FROM vulnerabilities v
             JOIN projects p ON v.project_id = p.id WHERE v.id = $1`,
            [req.params.id]
        );
        const vuln = vulnRes.rows[0];

        if (vuln) {
            await db.query('UPDATE vulnerabilities SET status = $1 WHERE id = $2', ['OPEN', req.params.id]);

            const desc = `Finding reopened: ${vuln.cve} in '${vuln.project}'.`;
            await db.query(
                'INSERT INTO alerts (type, title, desc_text) VALUES ($1, $2, $3)',
                ['warning', 'Finding Reopened', desc]
            );

            // Audit logging
            await db.query(
                `INSERT INTO audit_logs (actor, role, action, outcome, details)
                 VALUES ($1, $2, $3, $4, $5)`,
                [actorName, userRole, 'vulnerability.reopen', 'SUCCESS', JSON.stringify({ vuln_id: req.params.id, cve: vuln.cve, project: vuln.project })]
            );

            res.json({ status: "success", vuln: { ...vuln, status: 'OPEN' } });
        } else {
            res.status(404).json({ error: "Vulnerability not found" });
        }
    } catch (err) {
        console.error("Error in reopen:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Ignore Finding (ADMIN, SECURITY_LEAD, DEVELOPER)
app.post('/api/v1/findings/:id/ignore', requireRole(['ADMIN', 'SECURITY_LEAD', 'DEVELOPER']), async (req, res) => {
    const userRole = req.headers['x-user-role'] || 'SECURITY_LEAD';
    const actorName = userRole === 'SECURITY_LEAD' ? 'Jane Doe' : (userRole === 'ADMIN' ? 'Admin User' : 'Dave Dev');
    const { reason } = req.body;

    if (!reason) {
        return res.status(400).json({ error: "Reason is required to ignore a finding." });
    }

    try {
        const vulnRes = await db.query(
            `SELECT v.*, p.name as project FROM vulnerabilities v
             JOIN projects p ON v.project_id = p.id WHERE v.id = $1`,
            [req.params.id]
        );
        const vuln = vulnRes.rows[0];

        if (vuln) {
            await db.query('UPDATE vulnerabilities SET status = $1 WHERE id = $2', ['IGNORED', req.params.id]);

            const desc = `Finding ignored: ${vuln.cve} in '${vuln.project}'. Reason: ${reason}`;
            await db.query(
                'INSERT INTO alerts (type, title, desc_text) VALUES ($1, $2, $3)',
                ['info', 'Finding Ignored', desc]
            );

            // Audit logging
            await db.query(
                `INSERT INTO audit_logs (actor, role, action, outcome, details)
                 VALUES ($1, $2, $3, $4, $5)`,
                [actorName, userRole, 'vulnerability.ignore', 'SUCCESS', JSON.stringify({ vuln_id: req.params.id, cve: vuln.cve, project: vuln.project, reason })]
            );

            res.json({ status: "success", vuln: { ...vuln, status: 'IGNORED' } });
        } else {
            res.status(404).json({ error: "Vulnerability not found" });
        }
    } catch (err) {
        console.error("Error in ignore:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Get Finding History
app.get('/api/v1/findings/:id/history', async (req, res) => {
    try {
        const historyRes = await db.query(
            `SELECT * FROM audit_logs WHERE details::text LIKE $1 ORDER BY created_at DESC`,
            [`%"vuln_id":"${req.params.id}"%`]
        );
        res.json(historyRes.rows);
    } catch (err) {
        console.error("Error fetching finding history:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Request Waiver (DEVELOPER, SECURITY_LEAD, ADMIN)
app.post('/api/v1/waive/:id/request', requireRole(['ADMIN', 'SECURITY_LEAD', 'DEVELOPER']), async (req, res) => {
    const userRole = req.headers['x-user-role'] || 'DEVELOPER';
    let requester_email = 'developer@shieldops.internal';
    let actorName = 'Dave Dev';
    if (userRole === 'SECURITY_LEAD') {
        requester_email = 'jane.doe@shieldops.internal';
        actorName = 'Jane Doe';
    } else if (userRole === 'ADMIN') {
        requester_email = 'admin@shieldops.internal';
        actorName = 'Admin User';
    }

    const { reason, expires_in_days } = req.body;
    const waiverReason = reason || 'Temporary bypass requested.';
    const days = parseInt(expires_in_days) || 30;

    try {
        const vulnRes = await db.query(
            `SELECT v.*, p.name as project FROM vulnerabilities v
             JOIN projects p ON v.project_id = p.id WHERE v.id = $1`,
            [req.params.id]
        );
        const vuln = vulnRes.rows[0];
        if (!vuln) {
            return res.status(404).json({ error: "Vulnerability not found" });
        }

        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + days);

        const insertRes = await db.query(
            `INSERT INTO waivers (vulnerability_id, requester_email, reason, status, expires_at)
             VALUES ($1, $2, $3, 'PENDING', $4) RETURNING id`,
            [req.params.id, requester_email, waiverReason, expiresAt]
        );
        const waiverId = insertRes.rows[0].id;

        // Audit log
        await db.query(
            `INSERT INTO audit_logs (actor, role, action, outcome, details)
             VALUES ($1, $2, $3, $4, $5)`,
            [actorName, userRole, 'vulnerability.waiver_request', 'SUCCESS', JSON.stringify({ vuln_id: req.params.id, cve: vuln.cve, project: vuln.project, waiver_id: waiverId, reason: waiverReason })]
        );

        res.json({ status: "success", message: "Waiver request submitted successfully.", waiver_id: waiverId });
    } catch (err) {
        console.error("Waiver request error:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Approve Waiver (ADMIN, SECURITY_LEAD)
app.post('/api/v1/waive/:id/approve', requireRole(['ADMIN', 'SECURITY_LEAD']), async (req, res) => {
    const userRole = req.headers['x-user-role'] || 'SECURITY_LEAD';
    let approver_email = 'jane.doe@shieldops.internal';
    let actorName = 'Jane Doe';
    if (userRole === 'ADMIN') {
        approver_email = 'admin@shieldops.internal';
        actorName = 'Admin User';
    }

    try {
        const vulnRes = await db.query(
            `SELECT v.*, p.name as project FROM vulnerabilities v
             JOIN projects p ON v.project_id = p.id WHERE v.id = $1`,
            [req.params.id]
        );
        const vuln = vulnRes.rows[0];
        if (!vuln) {
            return res.status(404).json({ error: "Vulnerability not found" });
        }

        // Find the latest pending waiver
        const waiverRes = await db.query(
            `SELECT id FROM waivers WHERE vulnerability_id = $1 AND status = 'PENDING' ORDER BY created_at DESC LIMIT 1`,
            [req.params.id]
        );
        
        let waiverId;
        if (waiverRes.rows.length === 0) {
            // Direct approved waiver creation
            const expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + 30);
            
            const insertRes = await db.query(
                `INSERT INTO waivers (vulnerability_id, requester_email, approver_email, reason, status, expires_at)
                 VALUES ($1, $2, $3, 'Direct waiver approval', 'APPROVED', $4) RETURNING id`,
                [req.params.id, approver_email, approver_email, expiresAt]
            );
            waiverId = insertRes.rows[0].id;
        } else {
            waiverId = waiverRes.rows[0].id;
            await db.query(
                `UPDATE waivers SET status = 'APPROVED', approver_email = $1, updated_at = now() WHERE id = $2`,
                [approver_email, waiverId]
            );
        }

        // Alert
        const desc = `Temporary exception approved for ${vuln.cve} in '${vuln.project}'.`;
        await db.query(
            'INSERT INTO alerts (type, title, desc_text) VALUES ($1, $2, $3)',
            ['high', 'Waiver Approved', desc]
        );
        // Audit logging
        await db.query(
            `INSERT INTO audit_logs (actor, role, action, outcome, details)
             VALUES ($1, $2, $3, $4, $5)`,
            [actorName, userRole, 'vulnerability.waive.approve', 'SUCCESS', JSON.stringify({ vuln_id: req.params.id, cve: vuln.cve, project: vuln.project })]
        );
        
        await enqueueNotification('SLACK', 'WAIVER_APPROVED', { vulnId: req.params.id, cve: vuln.cve, project: vuln.project });
        await enqueueNotification('JIRA', 'WAIVER_APPROVED', { vulnId: req.params.id, cve: vuln.cve, project: vuln.project });
        await enqueueNotification('EMAIL', 'WAIVER_APPROVED', { vulnId: req.params.id, cve: vuln.cve, project: vuln.project });

        res.json({ status: "success" });
    } catch (err) {
        console.error("Error approving waiver:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Reject Waiver (ADMIN, SECURITY_LEAD)
app.post('/api/v1/waive/:id/reject', requireRole(['ADMIN', 'SECURITY_LEAD']), async (req, res) => {
    const userRole = req.headers['x-user-role'] || 'SECURITY_LEAD';
    let approver_email = 'jane.doe@shieldops.internal';
    let actorName = 'Jane Doe';
    if (userRole === 'ADMIN') {
        approver_email = 'admin@shieldops.internal';
        actorName = 'Admin User';
    }

    try {
        const vulnRes = await db.query(
            `SELECT v.*, p.name as project FROM vulnerabilities v
             JOIN projects p ON v.project_id = p.id WHERE v.id = $1`,
            [req.params.id]
        );
        const vuln = vulnRes.rows[0];
        if (!vuln) {
            return res.status(404).json({ error: "Vulnerability not found" });
        }

        // Find latest pending waiver
        const waiverRes = await db.query(
            `SELECT id FROM waivers WHERE vulnerability_id = $1 AND status = 'PENDING' ORDER BY created_at DESC LIMIT 1`,
            [req.params.id]
        );
        
        if (waiverRes.rows.length === 0) {
            return res.status(400).json({ error: "No pending waiver request found to reject." });
        }

        const waiverId = waiverRes.rows[0].id;
        await db.query(
            `UPDATE waivers SET status = 'REJECTED', approver_email = $1, updated_at = now() WHERE id = $2`,
            [approver_email, waiverId]
        );

        // Audit logging
        await db.query(
            `INSERT INTO audit_logs (actor, role, action, outcome, details)
             VALUES ($1, $2, $3, $4, $5)`,
            [actorName, userRole, 'vulnerability.waive.reject', 'SUCCESS', JSON.stringify({ vuln_id: req.params.id, cve: vuln.cve, project: vuln.project })]
        );
        
        await enqueueNotification('SLACK', 'WAIVER_REJECTED', { vulnId: req.params.id, cve: vuln.cve, project: vuln.project });
        await enqueueNotification('JIRA', 'WAIVER_REJECTED', { vulnId: req.params.id, cve: vuln.cve, project: vuln.project });
        await enqueueNotification('EMAIL', 'WAIVER_REJECTED', { vulnId: req.params.id, cve: vuln.cve, project: vuln.project });

        res.json({ status: "success" });
    } catch (err) {
        console.error("Error rejecting waiver:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Backward compatibility or direct call route
app.post('/api/v1/waive/:id', requireRole(['ADMIN', 'SECURITY_LEAD', 'DEVELOPER']), async (req, res, next) => {
    const userRole = req.headers['x-user-role'] || 'SECURITY_LEAD';
    if (userRole === 'ADMIN' || userRole === 'SECURITY_LEAD') {
        req.url = `/api/v1/waive/${req.params.id}/approve`;
    } else {
        req.url = `/api/v1/waive/${req.params.id}/request`;
    }
    app.handle(req, res, next);
});

// 4. User Role changes persistence endpoint (stores in PostgreSQL + audit logs)
app.post('/api/v1/users/role', async (req, res) => {
    const { role } = req.body;
    const actorRole = req.headers['x-user-role'] || 'SECURITY_LEAD';
    
    let email = 'jane.doe@shieldops.internal';
    let actorName = 'Jane Doe';
    if (role === 'ADMIN') {
        email = 'admin@shieldops.internal';
        actorName = 'Admin User';
    } else if (role === 'DEVELOPER') {
        email = 'developer@shieldops.internal';
        actorName = 'Dave Dev';
    } else if (role === 'VIEWER') {
        email = 'viewer@shieldops.internal';
        actorName = 'Val View';
    }

    try {
        await db.query('UPDATE users SET role = $1 WHERE email = $2', [role, email]);
        
        await db.query(
            `INSERT INTO audit_logs (actor, role, action, outcome, details)
             VALUES ($1, $2, $3, $4, $5)`,
            [actorName, actorRole, 'user.role_change', 'SUCCESS', JSON.stringify({ updated_role: role, target_email: email })]
        );

        res.json({ status: "success", role, email });
    } catch (err) {
        console.error("Error updating user role:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// User Management Endpoint (ADMIN only)
app.post('/api/v1/users/:id/role', requireRole(['ADMIN']), async (req, res) => {
    const { role } = req.body;
    const userId = req.params.id;
    try {
        const userRes = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
        const user = userRes.rows[0];
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        await db.query('UPDATE users SET role = $1 WHERE id = $2', [role, userId]);

        await db.query(
            `INSERT INTO audit_logs (actor, role, action, outcome, details)
             VALUES ($1, $2, $3, $4, $5)`,
            ['Admin User', 'ADMIN', 'user.update_role', 'SUCCESS', JSON.stringify({ target_user: user.email, new_role: role })]
        );

        res.json({ status: "success", user_id: userId, new_role: role });
    } catch (err) {
        console.error("User management error:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// 5. Ingestion & CI/CD Pipeline Integration Endpoints
app.post('/api/v1/events/pipeline', async (req, res) => {
    const { project, ciSystem, branch, commit, trigger } = req.body;
    const runId = "run-" + Math.floor(Math.random() * 10000 + 90000);

    try {
        // Get or create project
        let projectRes = await db.query('SELECT id FROM projects WHERE name = $1', [project || "unnamed-project"]);
        let projectId;
        if (projectRes.rows.length === 0) {
            const defaultTenantId = '00000000-0000-0000-0000-000000000000';
            const insertProj = await db.query(
                'INSERT INTO projects (tenant_id, name, repository_url) VALUES ($1, $2, $3) RETURNING id',
                [defaultTenantId, project || "unnamed-project", `https://github.com/shieldops/${project || "unnamed-project"}`]
            );
            projectId = insertProj.rows[0].id;
        } else {
            projectId = projectRes.rows[0].id;
        }

        // Prevent duplicate pipeline execution
        const activeCheck = await db.query(
            `SELECT id FROM pipelines 
             WHERE project_id = $1 AND branch = $2 AND commit_sha = $3 
             AND status IN ('QUEUED', 'CLONING', 'SCANNING', 'ANALYZING', 'POLICY_CHECK')`,
            [projectId, branch || 'main', commit || 'unknown']
        );
        if (activeCheck.rows.length > 0) {
            return res.status(409).json({ 
                error: "Pipeline already running", 
                message: `An active pipeline run (${activeCheck.rows[0].id}) for project '${project}' branch '${branch}' commit '${commit}' is currently in progress.` 
            });
        }

        const defaultScans = {
            SAST: { name: "Semgrep", status: "RUNNING", progress: 0, count: 0 },
            SCA: { name: "Trivy", status: "QUEUED", progress: 0, count: 0 },
            SECRETS: { name: "Gitleaks", status: "QUEUED", progress: 0, count: 0 },
            CONTAINER: { name: "Trivy Image", status: "QUEUED", progress: 0, count: 0 },
            IAC: { name: "tfsec / Kube-linter", status: "QUEUED", progress: 0, count: 0 }
        };
        // Exclude DAST for CLI agent runs so allCompleted resolves correctly
        if (ciSystem !== 'cli-agent') {
            defaultScans.DAST = { name: "OWASP ZAP", status: "QUEUED", progress: 0, count: 0 };
        }
        defaultScans.correlation_id = req.correlationId;

        // Create pipeline in QUEUED status
        await db.query(
            `INSERT INTO pipelines (id, project_id, ci_system, branch, commit_sha, trigger_event, status, scans)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [runId, projectId, ciSystem || "api", branch || "main", commit || "unknown", trigger || "API trigger", 'QUEUED', defaultScans]
        );

        // Write audit log
        await db.query(
            `INSERT INTO audit_logs (actor, role, action, outcome, details)
             VALUES ($1, $2, $3, $4, $5)`,
            ['SYSTEM', 'ADMIN', 'pipeline.register', 'SUCCESS', JSON.stringify({ pipeline_id: runId, project })]
        );

        res.status(202).json({ status: "accepted", pipeline_id: runId });
    } catch (err) {
        console.error("Error creating pipeline run:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// SSE endpoint for pipeline logs
app.get('/api/v1/pipelines/:id/logs/stream', async (req, res) => {
    const pipelineId = req.params.id;
    
    // Set headers for SSE
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders(); // flush the headers to establish connection

    try {
        // Fetch historical logs
        const historyRes = await db.query(
            'SELECT * FROM pipeline_logs WHERE pipeline_id = $1 ORDER BY created_at ASC',
            [pipelineId]
        );
        for (const row of historyRes.rows) {
            res.write(`data: ${JSON.stringify(row)}\n\n`);
        }
    } catch (err) {
        console.error("Error fetching historical logs:", err);
    }

    // Listener for new logs
    const logListener = (logData) => {
        res.write(`data: ${JSON.stringify(logData)}\n\n`);
    };

    const eventName = `log-${pipelineId}`;
    pipelineEvents.on(eventName, logListener);

    // Clean up when client disconnects
    req.on('close', () => {
        pipelineEvents.removeListener(eventName, logListener);
    });
});

// Alert ingestion endpoint from scanners
app.post('/api/v1/ingest/scan-results', async (req, res) => {
    const { pipeline_id, scanner_type, scan_status, findings } = req.body;
    
    if (!pipeline_id || typeof pipeline_id !== 'string') {
        return res.status(400).json({ error: "Invalid request: pipeline_id must be a string." });
    }
    if (!scanner_type || typeof scanner_type !== 'string') {
        return res.status(400).json({ error: "Invalid request: scanner_type must be a string." });
    }
    if (!scan_status || !['PASSED', 'FAILED', 'RUNNING'].includes(scan_status)) {
        return res.status(400).json({ error: "Invalid request: scan_status must be PASSED, FAILED, or RUNNING." });
    }
    if (findings && !Array.isArray(findings)) {
        return res.status(400).json({ error: "Invalid request: findings must be an array." });
    }

    try {
        const pipelineRes = await db.query('SELECT p.*, proj.name as project FROM pipelines p JOIN projects proj ON p.project_id = proj.id WHERE p.id = $1', [pipeline_id]);
        const pipeline = pipelineRes.rows[0];

        if (!pipeline) {
            return res.status(404).json({ error: "Pipeline run not found" });
        }

        // Sequential transition tracker for CLI runners:
        // Transition to CLONING and then SCANNING when first scan result hits
        if (pipeline.status === 'QUEUED') {
            await db.query("UPDATE pipelines SET status = 'CLONING' WHERE id = $1", [pipeline_id]);
            console.log(`[Pipeline Orchestrator] Run ${pipeline_id} transitioned to status: CLONING`);
            // Quick simulation sleep for cloning, then move to SCANNING
            await new Promise(res => setTimeout(res, 200));
            await db.query("UPDATE pipelines SET status = 'SCANNING' WHERE id = $1", [pipeline_id]);
            console.log(`[Pipeline Orchestrator] Run ${pipeline_id} transitioned to status: SCANNING`);
            
            // Re-fetch pipeline state
            const refetch = await db.query('SELECT * FROM pipelines WHERE id = $1', [pipeline_id]);
            Object.assign(pipeline, refetch.rows[0]);
        }

        // Map body scanner type (e.g., SAST, SCA, SECRETS, CONTAINER, IAC, DAST)
        const scanKey = scanner_type;
        if (pipeline.scans[scanKey]) {
            pipeline.scans[scanKey].status = scan_status;
            pipeline.scans[scanKey].progress = 100;
            pipeline.scans[scanKey].count = findings ? findings.length : 0;
        }

        // Update scans column in DB
        await db.query('UPDATE pipelines SET scans = $1 WHERE id = $2', [pipeline.scans, pipeline_id]);

        // Fetch policies to determine isBlocking dynamically
        const resPolicies = await db.query('SELECT key, value FROM policies');
        const policies = {};
        resPolicies.rows.forEach(row => {
            policies[row.key] = row.value;
        });

        // Append findings to DB with standard mapping and duplicate checks
        if (findings && findings.length > 0) {
            for (const f of findings) {
                const vulnId = "VULN-" + Math.floor(Math.random() * 1000 + 100);
                
                // Ensure severity level matches DB Enum values
                let mappedSeverity = f.severity ? f.severity.toUpperCase() : 'MEDIUM';
                if (!['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(mappedSeverity)) {
                    mappedSeverity = 'MEDIUM';
                }

                // Determine if this finding blocks pipeline execution based on current compliance policies
                let isBlocking = false;
                if (scanner_type === "SECRETS" && policies.secretsBlock) {
                    isBlocking = true;
                } else if (policies.criticalBlock && (mappedSeverity === 'CRITICAL' || mappedSeverity === 'HIGH')) {
                    isBlocking = true;
                }

                // Insert into DB using standard unique constraint checks
                await db.query(
                    `INSERT INTO vulnerabilities (id, cve, title, description, scanner, scanner_name, project_id, file_path, line_number, severity, status, remediation, package_name, package_version, fixed_version, pipeline_id, rule_id, is_blocking)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
                     ON CONFLICT ON CONSTRAINT unique_pipeline_finding DO NOTHING`,
                    [
                        vulnId, f.cve || "CVE-UNKNOWN", f.title || "Vulnerability found", f.description || "No description provided.",
                        scanner_type, pipeline.scans[scanKey] ? pipeline.scans[scanKey].name : scanner_type,
                        pipeline.project_id, f.file || "unknown", f.line || 0, mappedSeverity, 'OPEN',
                        f.remediation || "No remediation steps suggested.", f.package || "generic", f.version || "0.0.0",
                        f.fixedVersion || "0.0.0", pipeline_id, f.cve || "CVE-UNKNOWN", isBlocking
                    ]
                );
            }
        }

        // Evaluate Gating Policy Decision on every result
        await evaluatePipelinePolicy(pipeline_id);

        res.json({ status: "success", message: "Scan results recorded." });
    } catch (err) {
        console.error("Error recording scan results:", err.message);
        
        // Transition to FAILED on errors
        try {
            await db.query("UPDATE pipelines SET status = 'FAILED', completed_at = now() WHERE id = $1", [pipeline_id]);
        } catch (innerErr) {
            console.error("Error setting failure state:", innerErr.message);
        }
        res.status(500).json({ error: "Internal server error" });
    }
});

// Check runner status gate
app.get('/api/v1/events/pipeline/:id/status', async (req, res) => {
    try {
        const result = await db.query('SELECT id, status FROM pipelines WHERE id = $1', [req.params.id]);
        const pipeline = result.rows[0];
        if (!pipeline) {
            return res.status(404).json({ error: "Pipeline not found" });
        }
        res.json({
            pipeline_id: pipeline.id,
            status: pipeline.status,
            overall_status: pipeline.status
        });
    } catch (err) {
        console.error("Error checking pipeline status:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// 6. Trigger Live Pipeline Simulation via Server Control - Enforced RBAC (ADMIN, SECURITY_LEAD, DEVELOPER)
app.post('/api/v1/events/pipeline/trigger', requireRole(['ADMIN', 'SECURITY_LEAD', 'DEVELOPER']), async (req, res) => {
    const projects = ["auth-service", "payment-gateway", "customer-portal", "search-api"];
    const ciSystems = ["github", "gitlab", "jenkins"];
    const branches = ["main", "feature/payments", "hotfix/cors", "patch-2.4"];
    
    const randomProject = projects[Math.floor(Math.random() * projects.length)];
    const randomCi = ciSystems[Math.floor(Math.random() * ciSystems.length)];
    const randomBranch = branches[Math.floor(Math.random() * branches.length)];
    const randomSha = Math.random().toString(16).substring(2, 9);
    const runId = "run-" + Math.floor(Math.random() * 10000 + 90000);

    try {
        // Get or create project
        let projectRes = await db.query('SELECT id FROM projects WHERE name = $1', [randomProject]);
        let projectId;
        if (projectRes.rows.length === 0) {
            const defaultTenantId = '00000000-0000-0000-0000-000000000000';
            const insertProj = await db.query(
                'INSERT INTO projects (tenant_id, name, repository_url) VALUES ($1, $2, $3) RETURNING id',
                [defaultTenantId, randomProject, `https://github.com/shieldops/${randomProject}`]
            );
            projectId = insertProj.rows[0].id;
        } else {
            projectId = projectRes.rows[0].id;
        }

        // Prevent duplicate pipeline execution
        const activeCheck = await db.query(
            `SELECT id FROM pipelines 
             WHERE project_id = $1 AND branch = $2 AND commit_sha = $3 
             AND status IN ('QUEUED', 'CLONING', 'SCANNING', 'ANALYZING', 'POLICY_CHECK')`,
            [projectId, randomBranch, randomSha]
        );
        if (activeCheck.rows.length > 0) {
            return res.status(409).json({ 
                error: "Pipeline already running", 
                message: `An active pipeline run (${activeCheck.rows[0].id}) for project '${randomProject}' branch '${randomBranch}' commit '${randomSha}' is currently in progress.` 
            });
        }

        const defaultScans = {
            SAST: { name: "Semgrep", status: "RUNNING", progress: 0, count: 0 },
            SCA: { name: "Trivy", status: "QUEUED", progress: 0, count: 0 },
            SECRETS: { name: "Gitleaks", status: "QUEUED", progress: 0, count: 0 },
            CONTAINER: { name: "Trivy Image", status: "QUEUED", progress: 0, count: 0 },
            IAC: { name: "tfsec / Kube-linter", status: "QUEUED", progress: 0, count: 0 },
            DAST: { name: "OWASP ZAP", status: "QUEUED", progress: 0, count: 0 }
        };
        defaultScans.correlation_id = req.correlationId;

        // Create pipeline in QUEUED status
        await db.query(
            `INSERT INTO pipelines (id, project_id, ci_system, branch, commit_sha, trigger_event, status, scans)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [runId, projectId, randomCi, randomBranch, randomSha, `git-push (dev-${randomSha})`, 'QUEUED', defaultScans]
        );

        // Audit logging
        await db.query(
            `INSERT INTO audit_logs (actor, role, action, outcome, details)
             VALUES ($1, $2, $3, $4, $5)`,
            ['SYSTEM', 'ADMIN', 'pipeline.trigger', 'SUCCESS', JSON.stringify({ pipeline_id: runId, project: randomProject })]
        );

        // Enqueue scan job instead of simulating locally
        await db.query('INSERT INTO scan_jobs (pipeline_id) VALUES ($1)', [runId]);

        const newPipeline = {
            id: runId,
            project: randomProject,
            ciSystem: randomCi,
            branch: randomBranch,
            commit: randomSha,
            trigger: `git-push (dev-${randomSha})`,
            status: "QUEUED",
            scans: defaultScans
        };

        res.json({ status: "success", pipeline: newPipeline });
    } catch (err) {
        console.error("Error triggering simulation pipeline:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// -------------------------------------------------------------
// 7. GitHub Webhook Signature Verification & Ingestion Endpoint
// -------------------------------------------------------------

// Middleware to verify GitHub webhook signatures and prevent duplicates
async function verifyGitHubWebhook(req, res, next) {
    const deliveryId = req.headers['x-github-delivery'];
    const event = req.headers['x-github-event'];
    const signatureHeader = req.headers['x-hub-signature-256'];

    if (!deliveryId || !event) {
        return res.status(400).json({ error: "Missing GitHub webhook headers" });
    }

    // Only process push events
    if (event !== 'push') {
        return res.status(202).json({ message: "Unsupported event ignored" });
    }

    // Check for duplicate delivery ID (idempotency check)
    try {
        const dupCheck = await db.query('SELECT 1 FROM processed_webhooks WHERE id = $1', [deliveryId]);
        if (dupCheck.rows.length > 0) {
            return res.status(200).json({ message: "Duplicate event already processed" });
        }
    } catch (err) {
        console.error("Idempotency check error:", err.message);
        return res.status(500).json({ error: "Database error" });
    }

    const payload = req.body;
    const repoUrl = payload.repository && payload.repository.html_url;

    if (!repoUrl) {
        return res.status(400).json({ error: "Invalid payload: missing repository URL" });
    }

    try {
        // Resolve project and its webhook secret
        const projectRes = await db.query('SELECT * FROM projects WHERE repository_url = $1', [repoUrl]);
        const project = projectRes.rows[0];

        if (!project) {
            return res.status(404).json({ error: `Project not registered for repository URL: ${repoUrl}` });
        }

        // Verify signature if project has secret or if global secret exists
        const secret = project.github_webhook_secret || process.env.GITHUB_WEBHOOK_SECRET;
        if (secret) {
            if (!signatureHeader) {
                return res.status(401).json({ error: "Missing signature header for verification" });
            }

            const [algorithm, signature] = signatureHeader.split('=');
            if (algorithm !== 'sha256') {
                return res.status(400).json({ error: "Unsupported signature algorithm" });
            }

            const hmac = crypto.createHmac('sha256', secret);
            const digest = hmac.update(req.rawBody).digest('hex');
            const expectedSignature = Buffer.from(digest, 'hex');
            const actualSignature = Buffer.from(signature, 'hex');

            if (expectedSignature.length !== actualSignature.length || !crypto.timingSafeEqual(expectedSignature, actualSignature)) {
                return res.status(401).json({ error: "Signature verification failed" });
            }
        }

        req.project = project;
        next();
    } catch (err) {
        console.error("Webhook processing authorization failed:", err.message);
        res.status(500).json({ error: "Authorization error" });
    }
}

// GitHub webhook receiver endpoint
app.post('/api/v1/webhooks/github', verifyGitHubWebhook, async (req, res) => {
    const deliveryId = req.headers['x-github-delivery'];
    const payload = req.body;
    const project = req.project;

    try {
        // Extract push information
        const ref = payload.ref || 'refs/heads/main';
        const branch = ref.replace('refs/heads/', '');
        const commitSha = payload.after || '0000000000000000000000000000000000000000';
        
        const headCommit = payload.head_commit || {};
        const author = headCommit.author ? (headCommit.author.username || headCommit.author.name) : (payload.pusher ? payload.pusher.name : 'GitHub Webhook');

        // Prevent duplicate pipeline execution
        const activeCheck = await db.query(
            `SELECT id FROM pipelines 
             WHERE project_id = $1 AND branch = $2 AND commit_sha = $3 
             AND status IN ('QUEUED', 'CLONING', 'SCANNING', 'ANALYZING', 'POLICY_CHECK')`,
            [project.id, branch, commitSha]
        );
        if (activeCheck.rows.length > 0) {
            return res.status(409).json({ 
                error: "Pipeline already running", 
                message: `An active pipeline run (${activeCheck.rows[0].id}) for project '${project.name}' branch '${branch}' commit '${commitSha}' is currently in progress.` 
            });
        }

        // Prevent duplicate webhook processing
        await db.query('INSERT INTO processed_webhooks (id) VALUES ($1) ON CONFLICT DO NOTHING', [deliveryId]);

        const runId = "run-" + Math.floor(Math.random() * 10000 + 90000);

        const defaultScans = {
            SAST: { name: "Semgrep", status: "RUNNING", progress: 0, count: 0 },
            SCA: { name: "Trivy", status: "QUEUED", progress: 0, count: 0 },
            SECRETS: { name: "Gitleaks", status: "QUEUED", progress: 0, count: 0 },
            CONTAINER: { name: "Trivy Image", status: "QUEUED", progress: 0, count: 0 },
            IAC: { name: "tfsec / Kube-linter", status: "QUEUED", progress: 0, count: 0 },
            DAST: { name: "OWASP ZAP", status: "QUEUED", progress: 0, count: 0 }
        };
        defaultScans.correlation_id = req.correlationId;

        // Automatically create pipeline run in QUEUED status
        await db.query(
            `INSERT INTO pipelines (id, project_id, ci_system, branch, commit_sha, trigger_event, status, scans)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [runId, project.id, 'github', branch, commitSha, `git-push (${author})`, 'QUEUED', defaultScans]
        );

        // Write audit log
        await db.query(
            `INSERT INTO audit_logs (actor, role, action, outcome, details)
             VALUES ($1, $2, $3, $4, $5)`,
            [author, 'DEVELOPER', 'webhook.github.push', 'SUCCESS', JSON.stringify({ pipeline_id: runId, project: project.name, delivery_id: deliveryId })]
        );

        // Enqueue scan job
        await db.query('INSERT INTO scan_jobs (pipeline_id) VALUES ($1)', [runId]);

        res.status(202).json({
            status: "accepted",
            message: "Pipeline successfully spawned from webhook push",
            pipeline_id: runId
        });
    } catch (err) {
        console.error("Webhook route execution error:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Centralized error handling middleware
app.use((err, req, res, next) => {
    logger.error("Unhandled error encountered", { error: err.message, stack: err.stack });
    res.status(500).json({ error: "Internal server error" });
});

// Graceful shutdown helper
let isShuttingDownServer = false;
async function handleShutdown(server) {
    if (isShuttingDownServer) return;
    isShuttingDownServer = true;
    logger.info("Graceful shutdown initiated...");
    
    if (server) {
        server.close(async () => {
            logger.info("HTTP server closed.");
            try {
                await db.pool.end();
                logger.info("Database pool closed. Exited.");
                process.exit(0);
            } catch (err) {
                logger.error("Error during DB pool shutdown", { error: err.message });
                process.exit(1);
            }
        });
    } else {
        process.exit(0);
    }

    setTimeout(() => {
        logger.error("Forced shutdown due to timeout.");
        process.exit(1);
    }, 10000);
}

if (require.main === module) {
    // Start database pooling initialization and listen
    db.initDatabase()
        .then(() => {
            const server = app.listen(PORT, () => {
                logger.info(`ShieldOps Security Dashboard Server running at http://localhost:${PORT}`);
            });

            process.on('SIGTERM', () => handleShutdown(server));
            process.on('SIGINT', () => handleShutdown(server));
        })
        .catch(err => {
            logger.error("Database migration initialization failed! Server shutting down.", { error: err });
            process.exit(1);
        });
}

module.exports = app;
