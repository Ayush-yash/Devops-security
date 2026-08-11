const client = require('prom-client');

// Create a Registry
const register = new client.Registry();

// Add default metrics (CPU, Memory usage, etc.)
client.collectDefaultMetrics({ register });

// Define Metrics
const httpRequestsTotal = new client.Counter({
    name: 'http_requests_total',
    help: 'Total number of HTTP requests processed',
    labelNames: ['method', 'route', 'status'],
    registers: [register]
});

const httpRequestDuration = new client.Histogram({
    name: 'http_request_duration_seconds',
    help: 'Duration of HTTP requests in seconds',
    labelNames: ['method', 'route', 'status'],
    buckets: [0.1, 0.3, 0.5, 1, 1.5, 2, 3, 5],
    registers: [register]
});

const apiErrorsTotal = new client.Counter({
    name: 'api_errors_total',
    help: 'Total number of API request execution errors',
    labelNames: ['route', 'error_type'],
    registers: [register]
});

const pipelinesTotal = new client.Counter({
    name: 'pipelines_total',
    help: 'Total number of pipeline runs completed or triggered',
    labelNames: ['status'], // queued, running, passed, failed, blocked
    registers: [register]
});

const securityFindingsTotal = new client.Gauge({
    name: 'security_findings_total',
    help: 'Current active vulnerability count grouped by severity and scanner type',
    labelNames: ['severity', 'scanner'],
    registers: [register]
});

const scannerDuration = new client.Histogram({
    name: 'scanner_duration_seconds',
    help: 'Vulnerability scanner execution duration in seconds',
    labelNames: ['scanner_type'],
    buckets: [1, 2, 5, 10, 20, 30, 45, 60],
    registers: [register]
});

const scannerFailuresTotal = new client.Counter({
    name: 'scanner_failures_total',
    help: 'Total number of security scanner process execution failures',
    labelNames: ['scanner_type'],
    registers: [register]
});

const workerJobsTotal = new client.Counter({
    name: 'worker_jobs_total',
    help: 'Total number of background queue worker jobs processed',
    labelNames: ['job_type', 'status'], // success, failed
    registers: [register]
});

const workerFailuresTotal = new client.Counter({
    name: 'worker_failures_total',
    help: 'Total number of background queue worker job failures',
    labelNames: ['job_type'],
    registers: [register]
});

module.exports = {
    register,
    httpRequestsTotal,
    httpRequestDuration,
    apiErrorsTotal,
    pipelinesTotal,
    securityFindingsTotal,
    scannerDuration,
    scannerFailuresTotal,
    workerJobsTotal,
    workerFailuresTotal
};
