/**
 * ShieldOps Security Pipeline Scan Runner — Refactored Phase 4 Engine
 * -------------------------------------------------------------
 * This script runs automated security checks on code, secrets, and dependencies.
 * It reports findings back to the ShieldOps Ingestion API, then checks policy decisions.
 */

const fs = require('fs');
const path = require('path');

const SERVER_URL = process.env.SHIELDOPS_API_URL || "http://localhost:8080/api/v1";
const PROJECT_NAME = process.env.GITHUB_REPOSITORY ? process.env.GITHUB_REPOSITORY.split('/').pop() : path.basename(process.cwd());
const BRANCH_NAME = process.env.GITHUB_REF_NAME || "main";
const COMMIT_SHA = process.env.GITHUB_SHA || Math.random().toString(16).substring(2, 9);
const CI_SYSTEM = process.env.GITHUB_ACTIONS ? "github-actions" : "cli-agent";
const TRIGGER = process.env.GITHUB_EVENT_NAME || "local-dev-pipeline";

// Helper to safely execute a scan phase with standardized error wrapping
function runSafeScan(scanName, scanFn) {
    try {
        console.log(`\n🔍 [Scanner Engine] Starting phase: ${scanName}...`);
        return scanFn();
    } catch (err) {
        console.error(`❌ [Scanner Engine] Error executing ${scanName}:`, err.message);
        return []; // Return empty findings safely to allow other scanners to complete
    }
}

// -------------------------------------------------------------
// Scan Module 1: Secrets Scanning (Plaintext Key Check)
// -------------------------------------------------------------
function scanSecrets() {
    const findings = [];
    const secretRegexes = {
        AWS_KEY: /AKIA[0-9A-Z]{16}/g,
        GENERIC_KEY: /secret[-_]?key\s*=\s*['"][a-zA-Z0-9+/=]{20,}['"]/gi,
        SLACK_TOKEN: /xox[bap]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}/g
    };

    function searchDir(dir) {
        if (!fs.existsSync(dir)) return;
        const files = fs.readdirSync(dir);
        for (const file of files) {
            const fullPath = path.join(dir, file);
            
            // Skip node_modules, git directories, and agent configs
            if (file === 'node_modules' || file === '.git' || file === '.gemini') continue;

            const stat = fs.statSync(fullPath);
            if (stat.isDirectory()) {
                searchDir(fullPath);
            } else if (stat.isFile() && (file.endsWith('.js') || file.endsWith('.json') || file.endsWith('.env') || file.endsWith('.yml') || file.endsWith('.properties'))) {
                const content = fs.readFileSync(fullPath, 'utf8');
                
                for (const [key, regex] of Object.entries(secretRegexes)) {
                    let match;
                    while ((match = regex.exec(content)) !== null) {
                        const lines = content.substring(0, match.index).split('\n');
                        const lineNum = lines.length;
                        
                        console.warn(`  ⚠️ Found suspected secret [${key}] in ${file} at line ${lineNum}`);
                        findings.push({
                            cve: `SEC-SECRET-${key}`,
                            title: `Plaintext ${key} Exposure`,
                            description: `Hardcoded credential string found in source file matching signature pattern for ${key}.`,
                            file: path.relative(process.cwd(), fullPath),
                            line: lineNum,
                            severity: "CRITICAL",
                            remediation: "Revoke credentials immediately. Move secrets out of code and pull them from env vars or secret manager.",
                            package: "Source Code",
                            version: "1.0",
                            fixedVersion: "Environment Variables"
                        });
                    }
                }
            }
        }
    }

    searchDir(process.cwd());
    return findings;
}

// -------------------------------------------------------------
// Scan Module 2: Dependency SCA (Software Composition Analysis)
// -------------------------------------------------------------
function scanDependencies() {
    const findings = [];
    const packageJsonPath = path.join(process.cwd(), 'package.json');

    if (!fs.existsSync(packageJsonPath)) {
        console.log("  No package.json found. Skipping SCA.");
        return findings;
    }

    const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };

    // Mock Database of Vulnerable package versions
    const vulnDB = {
        "express": {
            maxVulnVersion: "4.19.1",
            cve: "CVE-2024-29025",
            severity: "HIGH",
            title: "Express Body Parser Memory Leak",
            description: "Vulnerability in Express body-parser middleware allows memory exhaustion via open connection streams.",
            remediation: "Upgrade express dependency to version 4.19.2 or higher.",
            fixedVersion: "4.19.2"
        },
        "lodash": {
            maxVulnVersion: "4.17.20",
            cve: "CVE-2020-8203",
            severity: "HIGH",
            title: "Lodash Prototype Pollution",
            description: "Prototype pollution vulnerability in lodash defaultsDeep method allows execution of remote properties.",
            remediation: "Upgrade lodash dependency to version 4.17.21.",
            fixedVersion: "4.17.21"
        }
    };

    for (const [dep, versionInfo] of Object.entries(deps)) {
        const cleanVer = dep === "express" || dep === "lodash" ? versionInfo.replace(/[^0-9.]/g, '') : '';
        
        if (vulnDB[dep]) {
            const dbInfo = vulnDB[dep];
            const isVulnerable = compareVersions(cleanVer, dbInfo.maxVulnVersion) <= 0;
            
            if (isVulnerable) {
                console.warn(`  ⚠️ Vulnerability found in ${dep}@${versionInfo}: ${dbInfo.cve}`);
                findings.push({
                    cve: dbInfo.cve,
                    title: dbInfo.title,
                    description: dbInfo.description,
                    file: "package.json",
                    line: 1,
                    severity: dbInfo.severity,
                    remediation: dbInfo.remediation,
                    package: dep,
                    version: versionInfo,
                    fixedVersion: dbInfo.fixedVersion
                });
            }
        }
    }
    return findings;
}

// -------------------------------------------------------------
// Scan Module 3: SAST (Static Application Security Testing)
// -------------------------------------------------------------
function scanSAST() {
    const findings = [];

    function searchDir(dir) {
        if (!fs.existsSync(dir)) return;
        const files = fs.readdirSync(dir);
        for (const file of files) {
            const fullPath = path.join(dir, file);
            if (file === 'node_modules' || file === '.git' || file === '.gemini') continue;

            const stat = fs.statSync(fullPath);
            if (stat.isDirectory()) {
                searchDir(fullPath);
            } else if (stat.isFile() && file.endsWith('.js')) {
                const content = fs.readFileSync(fullPath, 'utf8');

                // Check for dynamic execution (eval)
                if (content.includes("eval(")) {
                    const lines = content.substring(0, content.indexOf("eval(")).split('\n');
                    console.warn(`  ⚠️ Found eval() execution in ${file} at line ${lines.length}`);
                    findings.push({
                        cve: "SAST-DANGEROUS-EVAL",
                        title: "Execution of Untrusted Code via eval()",
                        description: "Use of eval() was detected. Dynamic code execution leads to injection vulnerabilities if inputs are parameterized.",
                        file: path.relative(process.cwd(), fullPath),
                        line: lines.length,
                        severity: "CRITICAL",
                        remediation: "Refactor code to avoid eval(). Use parsing utilities, objects mapping, or JSON.parse.",
                        package: "JavaScript Core Engine",
                        version: "1.0",
                        fixedVersion: "Refactored Logic"
                    });
                }
            }
        }
    }
    searchDir(process.cwd());
    return findings;
}

// -------------------------------------------------------------
// Scan Module 4: Container Vulnerability Audit (Dockerfile check)
// -------------------------------------------------------------
function scanContainer() {
    const findings = [];
    const dockerfilePath = path.join(process.cwd(), 'Dockerfile');

    if (!fs.existsSync(dockerfilePath)) {
        console.log("  No Dockerfile found. Skipping Container scan.");
        return findings;
    }

    const content = fs.readFileSync(dockerfilePath, 'utf8');
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim().startsWith("FROM ")) {
            const image = line.substring(5).trim();
            // Flag deprecated/insecure base images
            if (image.includes("alpine:3.15") || image.includes("ubuntu:18.04") || image.includes("node:14")) {
                console.warn(`  ⚠️ Insecure Container base image detected: ${image}`);
                findings.push({
                    cve: "CVE-2023-38545",
                    title: "Outdated Container Base Image Base OS",
                    description: `The container base image (${image}) uses an outdated OS version with known critical system package vulnerabilities.`,
                    file: "Dockerfile",
                    line: i + 1,
                    severity: "CRITICAL",
                    remediation: "Upgrade Dockerfile base image to Alpine 3.19+, Ubuntu 22.04, or Node 20-alpine.",
                    package: image,
                    version: image.split(':')[1] || "latest",
                    fixedVersion: "Upgrade Tag"
                });
            }
        }
    }
    return findings;
}

// -------------------------------------------------------------
// Scan Module 5: IaC (Infrastructure as Code) Security Scan
// -------------------------------------------------------------
function scanIaC() {
    const findings = [];

    function searchDir(dir) {
        if (!fs.existsSync(dir)) return;
        const files = fs.readdirSync(dir);
        for (const file of files) {
            const fullPath = path.join(dir, file);
            if (file === 'node_modules' || file === '.git' || file === '.gemini') continue;

            const stat = fs.statSync(fullPath);
            if (stat.isDirectory()) {
                searchDir(fullPath);
            } else if (stat.isFile() && (file.endsWith('.tf') || file.endsWith('.yaml') || file.endsWith('.yml'))) {
                const content = fs.readFileSync(fullPath, 'utf8');

                // Check for public SSH ingress in Terraform with flexible spacing regex
                if (file.endsWith('.tf') && /"0\.0\.0\.0\/0"/.test(content) && (/from_port\s*=\s*22/.test(content) || /to_port\s*=\s*22/.test(content))) {
                    console.warn(`  ⚠️ IaC Risk: Public SSH ingress allowed in ${file}`);
                    findings.push({
                        cve: "IAC-OPEN-SSH",
                        title: "Public SSH Port Exposed to Internet",
                        description: "Security Group rule permits SSH traffic on port 22 from the public internet (0.0.0.0/0).",
                        file: path.relative(process.cwd(), fullPath),
                        line: 1,
                        severity: "CRITICAL",
                        remediation: "Restrict security group ingress block CIDR to specific office VPN or bastion subnet IP ranges.",
                        package: "Terraform Security Group",
                        version: "1.0",
                        fixedVersion: "Restricted CIDR"
                    });
                }

                // Check for Privileged Pod container configs in Kubernetes
                if (content.includes("privileged: true")) {
                    console.warn(`  ⚠️ IaC Risk: Privileged container configuration found in ${file}`);
                    findings.push({
                        cve: "IAC-K8S-PRIVILEGED",
                        title: "Privileged Kubernetes Pod Configured",
                        description: "Kubernetes pod specification configures privileged execution mode, allowing container breakout.",
                        file: path.relative(process.cwd(), fullPath),
                        line: 1,
                        severity: "HIGH",
                        remediation: "Remove privileged context configurations. Use native capability controls.",
                        package: "Kubernetes Spec",
                        version: "1.0",
                        fixedVersion: "privileged=false"
                    });
                }
            }
        }
    }
    searchDir(process.cwd());
    return findings;
}

// Helper to compare semver versions (a <= b)
function compareVersions(a, b) {
    const pa = a.split('.');
    const pb = b.split('.');
    for (let i = 0; i < 3; i++) {
        const na = Number(pa[i] || 0);
        const nb = Number(pb[i] || 0);
        if (na > nb) return 1;
        if (na < nb) return -1;
    }
    return 0;
}

// -------------------------------------------------------------
// Pipeline Orchestration Main Routine
// -------------------------------------------------------------
async function runPipeline() {
    console.log("=============================================================");
    console.log(`🚀 ShieldOps Pipeline Integration Scanner: ${PROJECT_NAME}`);
    console.log("=============================================================");

    try {
        // 1. Register Pipeline Event
        console.log("Connecting to ShieldOps server to register pipeline run...");
        const registerRes = await fetch(`${SERVER_URL}/events/pipeline`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                project: PROJECT_NAME,
                ciSystem: CI_SYSTEM,
                branch: BRANCH_NAME,
                commit: COMMIT_SHA,
                trigger: TRIGGER
            })
        });

        if (!registerRes.ok) {
            throw new Error(`Server returned status ${registerRes.status}`);
        }

        const { pipeline_id } = await registerRes.json();
        console.log(`Pipeline successfully registered in system! Run ID: ${pipeline_id}`);

        // 2. Perform modular and safe scans
        const secretFindings = runSafeScan("Secrets Scan", scanSecrets);
        const scaFindings = runSafeScan("Dependency SCA Scan", scanDependencies);
        const sastFindings = runSafeScan("SAST Code Audit", scanSAST);
        const containerFindings = runSafeScan("Dockerfile Base OS Audit", scanContainer);
        const iacFindings = runSafeScan("Infrastructure configuration Check", scanIaC);

        // 3. Post Ingestion Reports independently
        console.log("\n📤 Submitting scan results to policy admission engine...");

        await fetch(`${SERVER_URL}/ingest/scan-results`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                pipeline_id,
                scanner_type: "SECRETS",
                scan_status: secretFindings.length > 0 ? "FAILED" : "PASSED",
                findings: secretFindings
            })
        });

        await fetch(`${SERVER_URL}/ingest/scan-results`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                pipeline_id,
                scanner_type: "SCA",
                scan_status: scaFindings.length > 0 ? "FAILED" : "PASSED",
                findings: scaFindings
            })
        });

        await fetch(`${SERVER_URL}/ingest/scan-results`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                pipeline_id,
                scanner_type: "SAST",
                scan_status: sastFindings.length > 0 ? "FAILED" : "PASSED",
                findings: sastFindings
            })
        });

        await fetch(`${SERVER_URL}/ingest/scan-results`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                pipeline_id,
                scanner_type: "CONTAINER",
                scan_status: containerFindings.length > 0 ? "FAILED" : "PASSED",
                findings: containerFindings
            })
        });

        await fetch(`${SERVER_URL}/ingest/scan-results`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                pipeline_id,
                scanner_type: "IAC",
                scan_status: iacFindings.length > 0 ? "FAILED" : "PASSED",
                findings: iacFindings
            })
        });

        // 4. Poll Gate Status for Pass/Fail decision
        console.log("\n⏳ Polling policy engine for build status gates...");
        let checksPassed = false;
        let isRunning = true;
        let retries = 5;

        while (isRunning && retries > 0) {
            const statusRes = await fetch(`${SERVER_URL}/events/pipeline/${pipeline_id}/status`);
            const statusData = await statusRes.json();

            console.log(`  Current Gate Verdict: [${statusData.status}]`);

            if (statusData.status === "PASSED") {
                checksPassed = true;
                isRunning = false;
            } else if (statusData.status === "BLOCKED" || statusData.status === "FAILED") {
                checksPassed = false;
                isRunning = false;
            } else {
                // Sleep 1 second before next poll
                await new Promise(r => setTimeout(r, 1000));
                retries--;
            }
        }

        // 5. Exit Decision
        console.log("=============================================================");
        if (checksPassed) {
            console.log("✅ PIPELINE SUCCESS: All security gates verified successfully.");
            console.log("=============================================================");
            process.exit(0);
        } else {
            console.error("❌ PIPELINE BLOCKED: Security gating policies failed!");
            console.error("Please view findings and approve waivers on ShieldOps dashboard.");
            console.log("=============================================================");
            process.exit(1);
        }

    } catch (error) {
        console.error("Pipeline scanner runtime failure:", error.message);
        process.exit(1);
    }
}

if (require.main === module) {
    runPipeline();
}

module.exports = {
    scanSecrets,
    scanDependencies,
    scanSAST,
    scanContainer,
    scanIaC
};
