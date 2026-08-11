# ShieldOps DevSecOps Pipeline Security Platform — End-to-End Walkthrough

This repository contains a fully functional, end-to-end local prototype of the DevSecOps Pipeline Security Platform. It includes a microservices architecture design, API specs, database schemas, an Express server, an interactive dashboard UI with Role-Based Access Control (RBAC), simulated Slack/Jira alerting, and a local scanning CLI agent that runs SAST, SCA, Secrets, Container, and IaC security checks.

---

## 🏃‍♂️ How to Run the End-to-End Project Locally

### 1. Initialize the Server
The Node.js Express server is already running in your background on port `8080`.
If you need to start or restart it manually in the future, run:
```bash
# Install dependencies
npm install

# Start Express static and API server
node server.js
```
The server serves:
- The dashboard frontend statically at: **[http://localhost:8080](http://localhost:8080)**
- The ingestion, findings, and gating policy REST APIs under `/api/v1/*`

### 2. Open the Centralized Dashboard
Open your browser and navigate to:
👉 **[http://localhost:8080](http://localhost:8080)**

Here, you will see the active dashboard showing aggregated findings.

### 3. Run a Pipeline Security Scan
Open a terminal in the root of the project and execute the pipeline scanner runner:
```bash
node scanner-runner.js
```
This script acts as the CI/CD pipeline step. It performs **five real security audits** on the workspace:
1. **Secrets Scan**: Searches the codebase for plaintext keys (like the mock AWS secret key in `server.js`).
2. **SCA Dependency Audit**: Parses `package.json` for dependencies and maps them to known vulnerabilities (like body-parser memory leak).
3. **SAST Code Check**: Audits Javascript files for unsafe dynamic execution (like `eval()`).
4. **Container Scan**: Scans the `Dockerfile` and flags insecure base tags (like the mock `FROM node:14`).
5. **IaC Security Scan**: Scans Terraform files (`main.tf`) and Kubernetes manifests for structural risks (like SSH exposed to the public `0.0.0.0/0`).

**What happens when it runs:**
- The script registers the run in the Ingestion API, runs the scans, and POSTs the reports back.
- Since OPA policies are enabled and critical issues exist, the Policy Engine returns **`BLOCKED`**.
- The scanner runner script prints warning logs and exits with **exit code `1`** (simulating a broken CI build).
- The Express server console output shows live dispatches:
  - **📢 [Slack Alert Dispatcher]** posts a block notification payload to `#security-alerts`.
  - **🎫 [Jira API Service]** automatically provisions an open Jira ticket for the findings.

### 4. Test Role-Based Access Control (RBAC)
1. On the dashboard header, locate the **User Role** dropdown selector.
2. Swap the active session to **Dave Dev (Developer)** or **Val View (Viewer/Auditor)**.
3. Switch to the **Policy Engine** tab:
   - Try toggling any of the OPA policy rules or changing the Slack/Jira configurations.
   - The UI blocks the request, displaying an alert: *“RBAC Authorization Failed: You do not have permission to modify active OPA Policy Bundles.”*
4. Go to the **Vulnerabilities** tab and click **Inspect** on a finding:
   - If logged in as **Val View (Viewer)**, the *Apply Auto-Remediation* and *Request Waiver* action triggers are disabled, and a notice is appended to the body.
   - If logged in as **Dave Dev (Developer)**, you can click **Request Waiver** and provide a reason. The finding will enter a **PENDING** waiver state.
   - If logged in as **Jane Doe (Security Lead)** or **Admin User**, you are granted full write permissions to remediate findings, and you can **Approve** or **Reject** pending waiver requests. Once approved, the finding is ignored by the OPA Policy Engine.

---

## 📁 Project Directory Structure

- [`server.js`](file:///c:/Users/Ayush%20Yash/Desktop/Devops%20security/server.js) — Express API and scan orchestration server (triggers Slack/Jira alerts).
- [`scanner-runner.js`](file:///c:/Users/Ayush%20Yash/Desktop/Devops%20security/scanner-runner.js) — The CLI scanning agent (SCA, SAST, secrets, Docker, Terraform checker).
- [`index.html`](file:///c:/Users/Ayush%20Yash/Desktop/Devops%20security/index.html) — Dashboard HTML layout (with RBAC header selectors & slack/jira toggles).
- [`style.css`](file:///c:/Users/Ayush%20Yash/Desktop/Devops%20security/style.css) — Premium dark-mode glassmorphism styling.
- [`app.js`](file:///c:/Users/Ayush%20Yash/Desktop/Devops%20security/app.js) — Frontend application controller with REST API data syncing.
- [`Dockerfile`](file:///c:/Users/Ayush%20Yash/Desktop/Devops%20security/Dockerfile) — Mock container base image config.
- [`main.tf`](file:///c:/Users/Ayush%20Yash/Desktop/Devops%20security/main.tf) — Mock Terraform network configuration.

### 📄 Architecture Documentation
- [`architecture_design.md`](file:///c:/Users/Ayush%20Yash/Desktop/Devops%20security/architecture_design.md) — Tech-stack align & high-level architecture.
- [`api_specifications.md`](file:///c:/Users/Ayush%20Yash/Desktop/Devops%20security/api_specifications.md) — API specifications.
- [`database_schemas.md`](file:///c:/Users/Ayush%20Yash/Desktop/Devops%20security/database_schemas.md) — Database structures (Postgres DDL, ES mappings, Redis cache).
- [`policy_engine_design.md`](file:///c:/Users/Ayush%20Yash/Desktop/Devops%20security/policy_engine_design.md) — OPA, Rego rules, and feedback mechanisms.
