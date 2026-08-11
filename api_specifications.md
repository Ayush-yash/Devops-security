# DevSecOps Platform - API Specifications

This document outlines the core RESTful APIs for the **API Gateway** and the **Ingestion Service**. These APIs form the boundary between external CI/CD tools, scanners, and the internal microservices of the DevSecOps platform.

---

## 1. API Gateway

The API Gateway is the central entry point. It is responsible for routing, rate-limiting, and issuing/validating authentication tokens.

### 1.1. Authentication
Generates a JWT (JSON Web Token) for CI/CD runners or API clients to authenticate subsequent requests.

*   **Endpoint:** `POST /api/v1/auth/token`
*   **Headers:**
    *   `Content-Type: application/json`
*   **Request Body:**
    ```json
    {
      "client_id": "org-ci-client-id-xyz",
      "client_secret": "secure-secret-token"
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "access_token": "eyJhbGciOiJIUzI1NiIsInR...",
      "token_type": "Bearer",
      "expires_in": 3600
    }
    ```

### 1.2. Health Check
*   **Endpoint:** `GET /api/v1/health`
*   **Response (200 OK):**
    ```json
    {
      "status": "healthy",
      "version": "1.0.4",
      "timestamp": "2026-08-09T17:15:00Z"
    }
    ```

---

## 2. Ingestion Service

The Ingestion Service accepts high-throughput event data from CI/CD systems and security scanners. All endpoints here are typically routed through the API Gateway and require a valid `Bearer` token.

### 2.1. Generic Pipeline Event Ingestion
Records the start, completion, or failure of a CI/CD pipeline. This event triggers the Scanner Orchestrator to evaluate what scans need to be run.

*   **Endpoint:** `POST /api/v1/events/pipeline`
*   **Headers:**
    *   `Authorization: Bearer <token>`
    *   `Content-Type: application/json`
*   **Request Body:**
    ```json
    {
      "event_type": "PIPELINE_STARTED",  // STARTED, COMPLETED, FAILED
      "pipeline_id": "run-84920",
      "project_name": "core-backend-api",
      "repository": "https://github.com/my-org/core-backend-api",
      "branch": "main",
      "commit_sha": "7a3b4c9d1e...",
      "trigger_actor": "jane.doe",
      "timestamp": "2026-08-09T17:15:30Z"
    }
    ```
*   **Response (202 Accepted):** (Returns quickly after publishing to Kafka)
    ```json
    {
      "status": "accepted",
      "event_id": "evt-9938-1122"
    }
    ```

### 2.2. CI/CD Specific Webhooks
For systems that can't construct the generic payload, the Ingestion Service provides dedicated endpoints that natively parse specific webhook formats.

*   **GitHub Webhook:** `POST /api/v1/webhooks/github`
    *   *Expects standard GitHub `X-GitHub-Event: push` or `workflow_run` payloads. Requires `X-Hub-Signature-256` validation.*
*   **GitLab Webhook:** `POST /api/v1/webhooks/gitlab`
    *   *Expects standard GitLab `X-Gitlab-Event: Pipeline Hook` payloads. Requires `X-Gitlab-Token` validation.*
*   **Response for all webhooks (202 Accepted):**
    ```json
    { "status": "accepted" }
    ```

### 2.3. Scan Result Ingestion
Allows external scanners (or internal worker nodes) to push normalized scan results back into the platform for policy evaluation and aggregation.

*   **Endpoint:** `POST /api/v1/ingest/scan-results`
*   **Headers:**
    *   `Authorization: Bearer <token>`
    *   `Content-Type: application/json`
*   **Request Body:**
    ```json
    {
      "pipeline_id": "run-84920",
      "scanner_name": "Trivy",
      "scanner_type": "CONTAINER_SCAN", // SAST, DAST, SCA, SECRETS, CONTAINER
      "scan_status": "SUCCESS",
      "execution_time_ms": 4500,
      "findings": [
        {
          "vulnerability_id": "CVE-2023-44487",
          "severity": "CRITICAL",
          "package": "golang.org/x/net",
          "version": "0.15.0",
          "fixed_version": "0.17.0",
          "title": "HTTP/2 Rapid Reset",
          "description": "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly...",
          "file": "go.mod"
        }
      ]
    }
    ```
*   **Response (202 Accepted):**
    ```json
    {
      "status": "accepted",
      "processed_findings_count": 1,
      "message": "Results pushed to policy engine queue"
    }
    ```

### 2.4. Pipeline Status Polling (Synchronous Gate)
Used by CI/CD plugins to poll whether a pipeline is allowed to proceed based on the Policy Engine's verdict.

*   **Endpoint:** `GET /api/v1/events/pipeline/{pipeline_id}/status`
*   **Headers:**
    *   `Authorization: Bearer <token>`
*   **Response (200 OK):**
    ```json
    {
      "pipeline_id": "run-84920",
      "overall_status": "FAILED", // PENDING, PASSED, FAILED
      "reason": "Policy violation: 1 CRITICAL vulnerability found in CONTAINER_SCAN",
      "details_url": "https://devsecops.my-org.com/pipelines/run-84920"
    }
    ```
