# ShieldOps DevSecOps Platform — Comprehensive Production Architecture & Implementation Details

This document provides a highly detailed, component-by-component breakdown of the ShieldOps platform. Use this as a guide for system design, system architecture, and technical interview discussions to demonstrate production-grade software engineering, security hardening, and reliability principles.

---

## Table of Contents
1. [System Architecture Overview](#1-system-architecture-overview)
2. [Database Schema Design & Locking Mechanics](#2-database-schema-design--locking-mechanics)
3. [Asynchronous Job Queue & Worker Architecture](#3-asynchronous-job-queue--worker-architecture)
4. [API Gateway Hardening & Security Protections](#4-api-gateway-hardening--security-protections)
5. [Policy Decision Engine & Waiver Workflows](#5-policy-decision-engine--waiver-workflows)
6. [Real-time Events (SSE) & Frontend Dashboard](#6-real-time-events-sse--frontend-dashboard)
7. [Observability & Request Correlation Tracing](#7-observability--request-correlation-tracing)
8. [CI/CD Git Integration (GitHub Webhooks & Actions)](#8-cicd-git-integration-github-webhooks--actions)
9. [Comprehensive Test Suite & Quality Assurance](#9-comprehensive-test-suite--quality-assurance)

---

## 1. System Architecture Overview

ShieldOps is designed around a **microservices-oriented, event-driven pattern** that decouples user interaction and API management from compute-intensive security scanning processes.

```
                           +------------------------+
                           |  Developer / GitHub    |
                           +-----------+------------+
                                       | (HTTP Push/Webhook)
                                       v
                           +-----------+------------+
                           |   API Server / Gateway | <----+ (Prometheus Scrape)
                           +-----+--------------+---+
                                 |              |
                    (Write Job)  |              | (SSE Real-time logs)
                                 v              v
      +------------+       +-----+----+   +-----+------+
      | PostgreSQL | <==== | Job Queue|   | Web UI     |
      | Database   |       +-----+----+   +------------+
      +-----+------+             |
            ^                    | (FIFO / SKIP LOCKED Pick-up)
            |                    v
            +================== +----------------------+
                                | Scan Worker Instance |
                                +----------------------+
```

### File Structure Map
- **`server.js`**: The main API server. Manages routing, rate-limiting, CORS, security headers, GitHub webhooks, Server-Sent Events (SSE) streams, and audit logging.
- **`worker.js`**: The queue-consumer service. Polls PostgreSQL for jobs, triggers the scanners, evaluates policies, and handles notification delivery.
- **`db.js`**: Connection pooling wrapper using the `pg` driver with automatic retry logic and database initialization routines.
- **`metrics.js`**: Centralized Prometheus instrumentation registry managing Gauges, Counters, and Histograms.
- **`logger.js`**: Structured JSON logging utility that formats standard logs and extracts `AggregateError` stack traces safely.
- **`scanner-runner.js`**: The static analysis scanning engine containing SAST (eval check), Secrets search (Regex matching), SCA (dependency lookup), Container image inspections, and Infrastructure as Code (IaC) verification rules.

---

## 2. Database Schema Design & Locking Mechanics

The schema is defined in [db/init.sql](file:///c:/Users/Ayush%20Yash/Desktop/Devops%20security/db/init.sql) and [db.js](file:///c:/Users/Ayush%20Yash/Desktop/Devops%20security/db.js).

### Core Entities
1. **`projects`**: Tenant mapping holding repository configurations.
2. **`pipelines`**: Represents build execution runs (`QUEUED`, `CLONING`, `SCANNING`, `ANALYZING`, `POLICY_CHECK`, `PASSED`, `FAILED`, `BLOCKED`). Stores scanner metadata inside a `JSONB` column.
3. **`vulnerabilities`**: Finding repository holding static details (CVE, file, line number, remediation, severity: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, status: `OPEN`, `RESOLVED`, `WAIVED`).
4. **`policies`**: Dynamic key-value gate definitions (e.g., `secretsBlock: true`, `criticalBlock: true`).
5. **`waivers`**: Tracks bypass request workflow states (`PENDING`, `APPROVED`, `REJECTED`) containing expiration timestamps.
6. **`scan_jobs`**: The message-broker equivalent table driving the worker orchestrator.

### Trigger-Based Events
We use PostgreSQL's native `LISTEN/NOTIFY` system to achieve real-time communications without polling:
```sql
CREATE OR REPLACE FUNCTION notify_pipeline_log() RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('pipeline_logs_channel', row_to_json(NEW)::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER pipeline_logs_notify_trigger
AFTER INSERT ON pipeline_logs
FOR EACH ROW EXECUTE PROCEDURE notify_pipeline_log();
```

---

## 3. Asynchronous Job Queue & Worker Architecture

To prevent API request-timeout errors during heavy static scans, ShieldOps uses a decoupled queue.

### Transactional Queue Polling (SKIP LOCKED)
Concurrency is safely managed across worker instances. The worker pulls jobs using a PostgreSQL transaction with pessimistic locking:
```javascript
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
```
*Why this is production-grade:*
- `FOR UPDATE`: Locks the selected row so no other database connection can modify it.
- `SKIP LOCKED`: Allows other worker instances to immediately skip over this locked row and grab the next available job, eliminating lock contention.
- **Exponential Backoff**: `POWER(2, retry_count) * INTERVAL '5 seconds'` dynamically calculates wait time before retrying a failed scan (e.g. 5s, 10s, 20s).

---

## 4. API Gateway Hardening & Security Protections

### 1. HTTP Security Headers (Helmet)
Uses `helmet` middleware to set context headers, restricting resource loading to same-origin domains and sanitizing cross-site injection points:
```javascript
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
```

### 2. Rate Limiting
Prevents API scraping and DoS vectors using IP sliding-window limiters:
```javascript
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 mins window
    max: 100, // max 100 requests per window
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many requests from this IP, please try again after 15 minutes." }
});
app.use('/api/', apiLimiter);
```

### 3. Role-Based Access Control (RBAC)
We enforce role restrictions via headers (`X-User-Role`) checking against predefined sets:
```javascript
function requireRole(allowedRoles) {
    return (req, res, next) => {
        const userRole = req.headers['x-user-role'];
        if (!userRole) {
            return res.status(401).json({ error: "Unauthorized: Missing X-User-Role header" });
        }
        if (!allowedRoles.includes(userRole.toUpperCase())) {
            return res.status(403).json({ error: `Forbidden: Role '${userRole}' does not have permission.` });
        }
        next();
    };
}
```

### 4. HMAC Webhook Verification
Ensures webhook payloads originate strictly from GitHub:
```javascript
const signature = req.headers['x-hub-signature-256'];
const hmac = crypto.createHmac('sha256', process.env.GITHUB_WEBHOOK_SECRET);
const digest = 'sha256=' + hmac.update(req.rawBody).digest('hex');
if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest))) {
    return res.status(401).json({ error: "Invalid HMAC Webhook Signature" });
}
```
*Note:* `crypto.timingSafeEqual` is utilized to block timing side-channel analysis.

---

## 5. Policy Decision Engine & Waiver Workflows

The OPA (Open Policy Agent) gate evaluates findings against configuration keys stored in the database:
- **`secretsBlock`**: If `true`, finding any exposed credential (e.g. AWS Keys) immediately sets pipeline status to `BLOCKED`.
- **`criticalBlock`**: Blocks the pipeline if any `CRITICAL` or `HIGH` vulnerabilities are reported.
- **`threshold`**: If the number of `HIGH` severity findings exceeds the maximum threshold, the build is blocked.

### Waiver Check Logic
If a pipeline contains a blocking vulnerability, the engine checks for an approved active waiver:
```javascript
const activeWaiver = await db.query(
    `SELECT * FROM waivers 
     WHERE vulnerability_id = $1 
       AND status = 'APPROVED' 
       AND expires_at > now()`, 
    [finding.id]
);
if (activeWaiver.rows.length > 0) {
    // Waiver is active; vulnerability is bypassed
}
```

---

## 6. Real-time Events (SSE) & Frontend Dashboard

Instead of expensive HTTP polling from the client, the UI utilizes **Server-Sent Events (SSE)** to display pipeline status changes and logs:
- The UI establishes a connection via `new EventSource('/api/v1/pipelines/events')`.
- The API server binds a listener to PostgreSQL's notification channel:
```javascript
pgClient.on('notification', (msg) => {
    if (msg.channel === 'pipeline_logs_channel') {
        res.write(`data: ${msg.payload}\n\n`);
    }
});
```

---

## 7. Observability & Request Correlation Tracing

### 1. Request Correlation ID
Every HTTP request gets assigned a unique `X-Correlation-ID` UUID. This ID is passed to DB write states and the background scanner worker:
```javascript
const correlationId = req.headers['x-correlation-id'] || crypto.randomUUID();
req.correlationId = correlationId;
res.setHeader('X-Correlation-ID', correlationId);
```
When debugging, DevOps engineers can search logs using `correlationId` to trace the entire lifecycle of a pipeline trigger across API gateways, databases, and background tasks.

### 2. Prometheus Instrumentation
Custom collectors gather metrics from the codebase:
- **`http_requests_total`**: Tracks total API requests by HTTP method, route, and status.
- **`http_request_duration_seconds`**: Tracks response times.
- **`security_findings_total`**: Gauges active vulnerabilities count.
- **`worker_jobs_total`**: Counter measuring worker queue efficiency.

---

## 8. CI/CD Git Integration (GitHub Webhooks & Actions)

The platform integrates directly with developers' workflows:
1. **GitHub Webhooks**: Pushes to `main` trigger webhook requests, enqueuing a scan job.
2. **GitHub Actions Workflow** ([.github/workflows/test.yml](file:///.github/workflows/test.yml)):
   - Runs automated Jest testing inside runner containers.
   - Installs PostgreSQL dynamically inside the workflow runner to validate database integration routines.

---

## 9. Comprehensive Test Suite & Quality Assurance

We use Jest to enforce automated testing:
1. **Unit Tests**: Verifies core algorithms (OPA policy evaluation, waiver bypass logic, JSON logging formats).
2. **Integration Tests**: Targets HTTP requests, CORS rejections, signature matching, and RBAC authentication headers.
3. **End-to-End Tests**: Simulates a complete flow: API registers pipeline -> worker executes static scanning scripts -> OPA gates results -> database updates statuses.
