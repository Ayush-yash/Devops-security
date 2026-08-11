-- ============================================================
-- SHIELDOPS DATABASE MIGRATION / INITIALIZATION SCHEMA
-- ============================================================

-- Enable pgcrypto for gen_random_uuid() if needed
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Drop tables if they exist to support clean reset
DROP TABLE IF EXISTS processed_webhooks CASCADE;
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS alerts CASCADE;
DROP TABLE IF EXISTS policy_evaluations CASCADE;
DROP TABLE IF EXISTS policies CASCADE;
DROP TABLE IF EXISTS waivers CASCADE;
DROP TABLE IF EXISTS vulnerabilities CASCADE;
DROP TABLE IF EXISTS scan_jobs CASCADE;
DROP TABLE IF EXISTS pipelines CASCADE;
DROP TABLE IF EXISTS pipeline_logs CASCADE;
DROP TABLE IF EXISTS projects CASCADE;
DROP TABLE IF EXISTS api_clients CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS tenants CASCADE;

-- Drop enums if they exist
DROP TYPE IF EXISTS user_role CASCADE;
DROP TYPE IF EXISTS waiver_status CASCADE;
DROP TYPE IF EXISTS tenant_plan CASCADE;
DROP TYPE IF EXISTS pipeline_status CASCADE;
DROP TYPE IF EXISTS scanner_type CASCADE;
DROP TYPE IF EXISTS scan_job_status CASCADE;
DROP TYPE IF EXISTS policy_type CASCADE;
DROP TYPE IF EXISTS policy_verdict CASCADE;
DROP TYPE IF EXISTS alert_channel_type CASCADE;
DROP TYPE IF EXISTS severity_level CASCADE;

-- Create Enums
CREATE TYPE user_role AS ENUM ('ADMIN', 'SECURITY_LEAD', 'DEVELOPER', 'VIEWER');
CREATE TYPE waiver_status AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED');
CREATE TYPE tenant_plan AS ENUM ('FREE', 'TEAM', 'BUSINESS', 'ENTERPRISE');
CREATE TYPE pipeline_status AS ENUM ('QUEUED', 'CLONING', 'SCANNING', 'ANALYZING', 'POLICY_CHECK', 'PASSED', 'BLOCKED', 'FAILED', 'ERROR', 'CANCELLED');
CREATE TYPE scanner_type AS ENUM ('SAST', 'DAST', 'SCA', 'SECRETS', 'CONTAINER', 'CONTAINER_SCAN', 'IAC_SCAN', 'IAC');
CREATE TYPE scan_job_status AS ENUM ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'TIMED_OUT', 'CANCELLED', 'PASSED');
CREATE TYPE policy_type AS ENUM ('GATE', 'ADVISORY', 'COMPLIANCE');
CREATE TYPE policy_verdict AS ENUM ('PASS', 'FAIL', 'WARN', 'ERROR');
CREATE TYPE alert_channel_type AS ENUM ('SLACK', 'TEAMS', 'JIRA', 'PAGERDUTY', 'EMAIL', 'WEBHOOK');
CREATE TYPE severity_level AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');

-- 1. tenants
CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(256) NOT NULL,
    slug            VARCHAR(128) NOT NULL UNIQUE,
    plan            tenant_plan NOT NULL DEFAULT 'FREE',
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. users
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email           VARCHAR(320) NOT NULL,
    display_name    VARCHAR(256) NOT NULL,
    role            user_role NOT NULL DEFAULT 'DEVELOPER',
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_users_tenant_email UNIQUE (tenant_id, email)
);

-- 3. projects
CREATE TABLE projects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(256) NOT NULL UNIQUE,
    repository_url  TEXT,
    default_branch  VARCHAR(256) NOT NULL DEFAULT 'main',
    github_webhook_secret VARCHAR(256),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 4. pipelines
CREATE TABLE pipelines (
    id                    VARCHAR(64) PRIMARY KEY, -- kept as VARCHAR to support run-XXXX string patterns
    project_id            UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    ci_system             VARCHAR(64) NOT NULL,
    branch                VARCHAR(256) NOT NULL,
    commit_sha            VARCHAR(64) NOT NULL,
    trigger_event         VARCHAR(256) NOT NULL,
    status                pipeline_status NOT NULL DEFAULT 'QUEUED',
    scans                 JSONB NOT NULL DEFAULT '{}',
    started_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at          TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 5. vulnerabilities
CREATE TABLE vulnerabilities (
    id              VARCHAR(64) PRIMARY KEY, -- e.g. VULN-001
    cve             VARCHAR(64) NOT NULL,
    title           VARCHAR(256) NOT NULL,
    description     TEXT NOT NULL,
    scanner         VARCHAR(64) NOT NULL,
    scanner_name    VARCHAR(128) NOT NULL,
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    file_path       VARCHAR(1024) NOT NULL,
    line_number     INT NOT NULL,
    severity        severity_level NOT NULL DEFAULT 'MEDIUM',
    status          VARCHAR(64) NOT NULL DEFAULT 'OPEN', -- OPEN, RESOLVED, WAIVED, IGNORED
    remediation     TEXT NOT NULL,
    package_name    VARCHAR(256),
    package_version VARCHAR(64),
    fixed_version   VARCHAR(64),
    pipeline_id     VARCHAR(64) REFERENCES pipelines(id) ON DELETE CASCADE,
    rule_id         VARCHAR(128),
    is_blocking     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT unique_pipeline_finding UNIQUE (pipeline_id, project_id, scanner, file_path, line_number, cve)
);

-- 5b. waivers (Time-bound exceptions for vulnerabilities)
CREATE TABLE waivers (
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

-- 6. policies (Toggle rules mapping)
CREATE TABLE policies (
    key             VARCHAR(64) PRIMARY KEY,
    value           BOOLEAN NOT NULL DEFAULT TRUE
);

-- 7. alerts
CREATE TABLE alerts (
    id              BIGSERIAL PRIMARY KEY,
    type            VARCHAR(64) NOT NULL,
    title           VARCHAR(256) NOT NULL,
    desc_text       TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 8. audit_logs
CREATE TABLE audit_logs (
    id              BIGSERIAL PRIMARY KEY,
    actor           VARCHAR(256) NOT NULL,
    role            VARCHAR(64) NOT NULL,
    action          VARCHAR(256) NOT NULL,
    outcome         VARCHAR(64) NOT NULL,
    details         JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 9. processed_webhooks
CREATE TABLE processed_webhooks (
    id              VARCHAR(128) PRIMARY KEY,
    processed_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 9. policy_evaluations
CREATE TABLE policy_evaluations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pipeline_id     VARCHAR(64) NOT NULL REFERENCES pipelines(id) ON DELETE CASCADE,
    policy_key      VARCHAR(64) NOT NULL REFERENCES policies(key) ON DELETE CASCADE,
    verdict         policy_verdict NOT NULL,
    reason          TEXT,
    evaluated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 10. pipeline_logs
CREATE TABLE pipeline_logs (
    id              BIGSERIAL PRIMARY KEY,
    pipeline_id     VARCHAR(64) NOT NULL REFERENCES pipelines(id) ON DELETE CASCADE,
    stage           VARCHAR(64) NOT NULL,
    severity        VARCHAR(64) NOT NULL,
    message         TEXT NOT NULL,
    details         JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- SEED DEFAULT DATA
-- ============================================================

-- Insert default Tenant
INSERT INTO tenants (id, name, slug, plan)
VALUES ('00000000-0000-0000-0000-000000000000', 'ShieldOps Tenant', 'shieldops-tenant', 'ENTERPRISE')
ON CONFLICT DO NOTHING;

-- Insert default Users representing RBAC session profiles
INSERT INTO users (id, tenant_id, email, display_name, role)
VALUES 
  ('11111111-1111-1111-1111-111111111111', '00000000-0000-0000-0000-000000000000', 'jane.doe@shieldops.internal', 'Jane Doe', 'SECURITY_LEAD'),
  ('22222222-2222-2222-2222-222222222222', '00000000-0000-0000-0000-000000000000', 'admin@shieldops.internal', 'Admin User', 'ADMIN'),
  ('33333333-3333-3333-3333-333333333333', '00000000-0000-0000-0000-000000000000', 'developer@shieldops.internal', 'Dave Dev', 'DEVELOPER'),
  ('44444444-4444-4444-4444-444444444444', '00000000-0000-0000-0000-000000000000', 'viewer@shieldops.internal', 'Val View', 'VIEWER')
ON CONFLICT DO NOTHING;

-- Insert default Projects
INSERT INTO projects (id, tenant_id, name, repository_url, github_webhook_secret)
VALUES 
  ('a0000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-000000000000', 'payment-gateway', 'https://github.com/shieldops/payment-gateway', 'test_webhook_secret'),
  ('b0000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-000000000000', 'auth-service', 'https://github.com/shieldops/auth-service', NULL),
  ('c0000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-000000000000', 'customer-portal', 'https://github.com/shieldops/customer-portal', NULL),
  ('d0000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-000000000000', 'search-api', 'https://github.com/shieldops/search-api', NULL)
ON CONFLICT DO NOTHING;

-- Insert default Policies (Toggles state)
INSERT INTO policies (key, value) VALUES
  ('criticalBlock', TRUE),
  ('secretsBlock', TRUE),
  ('licenseBlock', TRUE),
  ('registryBlock', FALSE),
  ('slackIntegration', TRUE),
  ('jiraIntegration', TRUE)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;

-- Insert default Pipelines
INSERT INTO pipelines (id, project_id, ci_system, branch, commit_sha, trigger_event, status, scans, created_at)
VALUES
  (
    'run-99482', 
    'a0000000-0000-0000-0000-000000000000', 
    'github', 
    'main', 
    '9bf4c21000000000000000000000000000000000', 
    'git-push (jane-doe)', 
    'BLOCKED', 
    '{
      "SAST": {"name": "Semgrep", "status": "PASSED", "progress": 100, "count": 0},
      "SCA": {"name": "Trivy", "status": "PASSED", "progress": 100, "count": 0},
      "SECRETS": {"name": "Gitleaks", "status": "PASSED", "progress": 100, "count": 0},
      "CONTAINER": {"name": "Trivy Image", "status": "FAILED", "progress": 100, "count": 1},
      "DAST": {"name": "OWASP ZAP", "status": "PASSED", "progress": 100, "count": 0}
    }'::jsonb,
    NOW() - INTERVAL '10 minutes'
  ),
  (
    'run-99481', 
    'b0000000-0000-0000-0000-000000000000', 
    'gitlab', 
    'auth-patch-1', 
    'f1a3e89000000000000000000000000000000000', 
    'merge_request (john-dev)', 
    'PASSED', 
    '{
      "SAST": {"name": "Semgrep", "status": "PASSED", "progress": 100, "count": 0},
      "SCA": {"name": "Trivy", "status": "PASSED", "progress": 100, "count": 0},
      "SECRETS": {"name": "Gitleaks", "status": "PASSED", "progress": 100, "count": 0},
      "CONTAINER": {"name": "Trivy Image", "status": "PASSED", "progress": 100, "count": 0},
      "DAST": {"name": "OWASP ZAP", "status": "PASSED", "progress": 100, "count": 0}
    }'::jsonb,
    NOW() - INTERVAL '18 minutes'
  )
ON CONFLICT DO NOTHING;

-- Insert default Vulnerabilities
INSERT INTO vulnerabilities (id, cve, title, description, scanner, scanner_name, project_id, file_path, line_number, severity, status, remediation, package_name, package_version, fixed_version, pipeline_id, created_at)
VALUES
  (
    'VULN-001',
    'CVE-2023-44487',
    'HTTP/2 Rapid Reset DDoS',
    'The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly.',
    'CONTAINER_SCAN',
    'Trivy',
    'a0000000-0000-0000-0000-000000000000',
    'docker-compose.yml',
    14,
    'CRITICAL',
    'OPEN',
    'Upgrade docker base image from golang:1.20-alpine to golang:1.21.3-alpine or set HTTP2_MAX_CONCURRENT_STREAMS to limits.',
    'golang.org/x/net',
    '0.15.0',
    '0.17.0',
    'run-99482',
    NOW() - INTERVAL '10 minutes'
  ),
  (
    'VULN-002',
    'CVE-2023-38545',
    'SOCKS5 Heap Buffer Overflow',
    'This flaw allows an attacker to overflow a heap-based buffer in curl''s SOCKS5 proxy handshake resolution code.',
    'SCA',
    'Trivy (SCA)',
    'b0000000-0000-0000-0000-000000000000',
    'package.json',
    48,
    'HIGH',
    'OPEN',
    'Run `npm update libcurl` or update dependency version to curl-8.4.0-r0 in Alpine package manager.',
    'libcurl',
    '8.2.1-r0',
    '8.4.0-r0',
    'run-99481',
    NOW() - INTERVAL '18 minutes'
  ),
  (
    'VULN-003',
    'SEC-AWS-048',
    'AWS Root Access Key Leaked',
    'Hardcoded plaintext AWS access key ID and secret access key discovered in source code repository.',
    'SECRETS',
    'Gitleaks',
    'c0000000-0000-0000-0000-000000000000',
    'config/aws.js',
    8,
    'CRITICAL',
    'OPEN',
    'Revoke AWS key pair ''AKIAIOSFODNN7EXAMPLE'' immediately in IAM console. Rotate credentials and integrate AWS Secrets Manager.',
    'aws-sdk',
    '2.12.0',
    'Use IAM Roles',
    NULL,
    NOW() - INTERVAL '30 minutes'
  ),
  (
    'VULN-004',
    'CVE-2022-22965',
    'Spring4Shell Remote Code Execution',
    'A Spring MVC or Spring WebFlux application running on JDK 9+ is vulnerable to remote code execution via data binding parameters.',
    'SAST',
    'Semgrep',
    'd0000000-0000-0000-0000-000000000000',
    'pom.xml',
    25,
    'CRITICAL',
    'OPEN',
    'Update parent pom framework version to org.springframework:spring-webmvc:5.3.18 or higher.',
    'spring-webmvc',
    '5.3.15',
    '5.3.18',
    NULL,
    NOW() - INTERVAL '40 minutes'
  )
ON CONFLICT DO NOTHING;

-- Insert default Alerts
INSERT INTO alerts (type, title, desc_text, created_at)
VALUES
  ('crit', 'Deployment Blocked', 'Pipeline run-99482 for ''payment-gateway'' blocked by OPA Rego rule ''fail_on_critical''.', NOW() - INTERVAL '10 minutes'),
  ('crit', 'API Secrets Leak', 'Gitleaks identified raw AWS Access Key in ''customer-portal'' project source code.', NOW() - INTERVAL '18 minutes')
ON CONFLICT DO NOTHING;
