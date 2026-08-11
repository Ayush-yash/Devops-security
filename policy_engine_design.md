# Policy Engine & OPA Integration — Design Document

**Platform:** DevSecOps Pipeline Security Platform
**Version:** 1.0
**Last Updated:** 2026-08-09
**Status:** Draft — Ready for Review

---

## Table of Contents

1. [Policy Engine Architecture](#1-policy-engine-architecture)
2. [OPA Integration](#2-opa-integration)
3. [Example Rego Policies](#3-example-rego-policies)
4. [Policy Evaluation Flow](#4-policy-evaluation-flow)
5. [CI/CD Feedback Loop](#5-cicd-feedback-loop)
6. [Governance & Audit](#6-governance--audit)

---

## 1. Policy Engine Architecture

### 1.1 Overview

The Policy Engine is the decision-making core of the DevSecOps platform. It operates as a stateless, horizontally scalable Go microservice that:

1. **Consumes** normalized scan results from the `scan-results.aggregated` Kafka topic.
2. **Loads** the tenant-specific policy configuration (cached in Redis, sourced from PostgreSQL).
3. **Evaluates** each applicable policy by constructing an OPA input document and querying the embedded OPA engine.
4. **Aggregates** individual policy verdicts into a final pipeline-level verdict (`PASSED`, `FAILED`, or `WARN`).
5. **Publishes** the verdict to the `pipeline.verdicts` Kafka topic for downstream consumption by the Alerting Service and CI/CD Callback handler.

### 1.2 Internal Components

| Component | Responsibility |
| :--- | :--- |
| **Kafka Consumer Group** | Consumes from `scan-results.aggregated` with at-least-once delivery semantics. Consumer group ID: `policy-engine-cg`. |
| **Tenant Policy Resolver** | Resolves the active policy set for the given `tenant_id` / `project_id`. Uses Redis as a read-through cache with a 60-second TTL, falling back to PostgreSQL. |
| **OPA Evaluator** | Embeds the OPA Go SDK (`github.com/open-policy-agent/opa/rego`). Loads pre-compiled Rego bundles and evaluates input documents against them. |
| **Verdict Aggregator** | Applies aggregation logic: if **any** policy returns `FAIL`, the overall verdict is `FAILED`. If all policies return `PASS` but one or more return `WARN`, the overall verdict is `WARN`. Otherwise, `PASSED`. |
| **Kafka Producer** | Publishes the final `PipelineVerdict` event to the `pipeline.verdicts` topic. Uses idempotent producer configuration to prevent duplicate verdicts. |
| **Audit Logger** | Writes a detailed, immutable evaluation record to PostgreSQL (`policy_evaluations` table) and optionally to Elasticsearch for full-text search and compliance querying. |

### 1.3 Service Configuration

```yaml
# policy-engine/config.yaml
service:
  name: policy-engine
  port: 8082
  log_level: info

kafka:
  brokers: ["kafka-0:9092", "kafka-1:9092", "kafka-2:9092"]
  consumer:
    group_id: policy-engine-cg
    topics: ["scan-results.aggregated"]
    auto_offset_reset: earliest
    max_poll_records: 50
  producer:
    topic: pipeline.verdicts
    idempotent: true
    acks: all

opa:
  mode: embedded            # embedded | sidecar
  bundle_path: /etc/opa/bundles
  bundle_poll_interval: 30s # how often to check for new bundles
  decision_log: true

redis:
  addr: redis-cluster:6379
  policy_cache_ttl: 60s

postgres:
  dsn: postgres://policy_svc:***@pg-primary:5432/devsecops
  max_open_conns: 25

metrics:
  prometheus_port: 9090
```

### 1.4 End-to-End Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant Kafka as Apache Kafka
    participant PE as Policy Engine
    participant Redis as Redis Cache
    participant PG as PostgreSQL
    participant OPA as OPA Embedded
    participant KafkaOut as Kafka Verdicts
    participant Alert as Alerting Service
    participant CICD as CI/CD Callback Handler

    Kafka->>PE: Consume scan-results.aggregated event
    PE->>PE: Deserialize and validate ScanResultEvent

    PE->>Redis: GET tenant:{tenant_id}:policies
    alt Cache Hit
        Redis-->>PE: Return cached PolicySet
    else Cache Miss
        PE->>PG: SELECT * FROM policies WHERE tenant_id = ? AND active = true
        PG-->>PE: Return PolicySet rows
        PE->>Redis: SET tenant:{tenant_id}:policies (TTL 60s)
    end

    loop For each Policy in PolicySet
        PE->>PE: Construct OPA Input Document
        PE->>OPA: rego.Eval(policy_package, input)
        OPA-->>PE: DecisionDocument {allow, violations[], severity}
        PE->>PE: Record individual policy verdict
    end

    PE->>PE: Aggregate verdicts into final PipelineVerdict
    PE->>PG: INSERT INTO policy_evaluations (audit record)

    PE->>KafkaOut: Publish PipelineVerdict event
    KafkaOut->>Alert: Consume verdict and dispatch alerts
    KafkaOut->>CICD: Consume verdict and update CI/CD status
```

### 1.5 Kafka Topic Schema

**Input Topic:** `scan-results.aggregated`

```json
{
  "event_id": "evt-agg-7821",
  "pipeline_id": "run-84920",
  "tenant_id": "tenant-acme-corp",
  "project_id": "proj-core-api",
  "repository": "https://github.com/acme/core-api",
  "branch": "main",
  "commit_sha": "7a3b4c9d1e...",
  "scan_types_completed": ["SAST", "SCA", "CONTAINER_SCAN", "SECRETS"],
  "aggregated_findings": [
    {
      "finding_id": "f-001",
      "scanner_type": "SCA",
      "severity": "CRITICAL",
      "vulnerability_id": "CVE-2023-44487",
      "package": "golang.org/x/net",
      "version": "0.15.0",
      "fixed_version": "0.17.0",
      "file": "go.mod"
    },
    {
      "finding_id": "f-002",
      "scanner_type": "SECRETS",
      "severity": "HIGH",
      "rule_id": "generic-api-key",
      "file": "src/config.js",
      "line": 42,
      "match": "REDACTED"
    }
  ],
  "metadata": {
    "trigger_actor": "jane.doe",
    "ci_tool": "github_actions",
    "callback_url": "https://api.github.com/repos/acme/core-api/check-runs/12345",
    "timestamp": "2026-08-09T17:15:30Z"
  }
}
```

**Output Topic:** `pipeline.verdicts`

```json
{
  "event_id": "evt-vrd-3301",
  "pipeline_id": "run-84920",
  "tenant_id": "tenant-acme-corp",
  "project_id": "proj-core-api",
  "commit_sha": "7a3b4c9d1e...",
  "overall_verdict": "FAILED",
  "reason": "2 policy violations detected",
  "policy_results": [
    {
      "policy_id": "pol-crit-vuln-gate",
      "policy_name": "Critical Vulnerability Gate",
      "version": "1.2.0",
      "verdict": "FAIL",
      "violations": [
        {
          "finding_id": "f-001",
          "message": "CRITICAL vulnerability CVE-2023-44487 in golang.org/x/net@0.15.0 -- fix available: 0.17.0"
        }
      ]
    },
    {
      "policy_id": "pol-secrets-gate",
      "policy_name": "Secrets Detection Gate",
      "version": "1.0.0",
      "verdict": "FAIL",
      "violations": [
        {
          "finding_id": "f-002",
          "message": "Secret detected: generic-api-key in src/config.js:42"
        }
      ]
    }
  ],
  "callback": {
    "ci_tool": "github_actions",
    "callback_url": "https://api.github.com/repos/acme/core-api/check-runs/12345"
  },
  "evaluated_at": "2026-08-09T17:15:31Z"
}
```

---

## 2. OPA Integration

### 2.1 Deployment Modes

The platform supports two deployment modes for OPA. The **embedded** mode is the default and recommended approach.

| Mode | Description | Pros | Cons |
| :--- | :--- | :--- | :--- |
| **Embedded (Default)** | OPA is compiled into the Policy Engine binary using the OPA Go SDK (`opa/rego`). The engine loads Rego bundles from disk or an HTTP bundle server. | Zero network latency for evaluations; single deployment artifact; simpler operational footprint. | Requires a Go service; bundle updates require a reload (not a redeployment). |
| **Sidecar** | OPA runs as a separate container in the same Kubernetes pod, exposed on `localhost:8181`. The Policy Engine calls OPA's REST API (`POST /v1/data/{package}`). | Language-agnostic; can be used with non-Go services; OPA can be independently upgraded. | Adds ~1-3ms network latency per evaluation; more complex pod spec; separate health/readiness probes needed. |

### 2.2 Embedded OPA -- Go SDK Usage

```go
package evaluator

import (
    "context"
    "fmt"
    "github.com/open-policy-agent/opa/rego"
    "github.com/open-policy-agent/opa/loader"
)

// OPAEvaluator wraps the OPA Go SDK for policy evaluation.
type OPAEvaluator struct {
    preparedQueries map[string]rego.PreparedEvalQuery
}

// NewOPAEvaluator loads all Rego bundles from the given path and
// pre-compiles them into prepared queries for fast evaluation.
func NewOPAEvaluator(bundlePath string) (*OPAEvaluator, error) {
    result, err := loader.NewFileLoader().All([]string{bundlePath})
    if err != nil {
        return nil, fmt.Errorf("failed to load bundles: %w", err)
    }

    // Pre-compile known policy packages
    packages := []string{
        "data.devsecops.vulnerability_gate",
        "data.devsecops.license_compliance",
        "data.devsecops.secrets_gate",
        "data.devsecops.container_image_policy",
    }

    prepared := make(map[string]rego.PreparedEvalQuery, len(packages))
    for _, pkg := range packages {
        r := rego.New(
            rego.Query(pkg),
            rego.ParsedBundle("policies", &result.Bundles["policies"]),
        )
        pq, err := r.PrepareForEval(context.Background())
        if err != nil {
            return nil, fmt.Errorf("failed to prepare query for %s: %w", pkg, err)
        }
        prepared[pkg] = pq
    }

    return &OPAEvaluator{preparedQueries: prepared}, nil
}

// Evaluate runs a specific policy against the provided input document.
func (e *OPAEvaluator) Evaluate(
    ctx context.Context,
    policyPackage string,
    input map[string]interface{},
) (map[string]interface{}, error) {
    pq, ok := e.preparedQueries[policyPackage]
    if !ok {
        return nil, fmt.Errorf("unknown policy package: %s", policyPackage)
    }

    rs, err := pq.Eval(ctx, rego.EvalInput(input))
    if err != nil {
        return nil, fmt.Errorf("evaluation failed: %w", err)
    }

    if len(rs) == 0 || len(rs[0].Expressions) == 0 {
        return nil, fmt.Errorf("no result from policy evaluation")
    }

    decision, ok := rs[0].Expressions[0].Value.(map[string]interface{})
    if !ok {
        return nil, fmt.Errorf("unexpected decision format")
    }
    return decision, nil
}
```

### 2.3 Policy Bundle Management

Policies are versioned and distributed as **OPA Bundles** -- tarball archives (`.tar.gz`) containing Rego files and optional JSON data files.

```mermaid
flowchart LR
    subgraph Authors["Policy Authors"]
        Dev["Security Engineer"]
    end

    subgraph VCS["Version Control"]
        Repo["policies-repo in Git"]
    end

    subgraph CI["Bundle CI Pipeline"]
        Lint["opa fmt + opa check"]
        Test["opa test ./..."]
        Build["opa build -b . -o bundle.tar.gz"]
        Sign["cosign sign-blob bundle.tar.gz"]
    end

    subgraph Registry["Bundle Registry"]
        OCI["OCI Registry e.g. GHCR / ECR"]
    end

    subgraph Runtime["Policy Engine Pods"]
        PE1["Pod 1 Embedded OPA"]
        PE2["Pod 2 Embedded OPA"]
        PE3["Pod N Embedded OPA"]
    end

    Dev -->|"git push"| Repo
    Repo -->|"triggers"| Lint
    Lint --> Test
    Test --> Build
    Build --> Sign
    Sign -->|"oci push"| OCI

    OCI -->|"periodic pull 30s"| PE1
    OCI -->|"periodic pull 30s"| PE2
    OCI -->|"periodic pull 30s"| PE3
```

**Bundle Directory Structure:**

```
policies/
├── devsecops/
│   ├── vulnerability_gate.rego
│   ├── vulnerability_gate_test.rego
│   ├── license_compliance.rego
│   ├── license_compliance_test.rego
│   ├── secrets_gate.rego
│   ├── secrets_gate_test.rego
│   ├── container_image_policy.rego
│   ├── container_image_policy_test.rego
│   └── data/
│       ├── banned_licenses.json
│       └── approved_registries.json
├── .manifest
└── .signatures.json
```

**Versioning Strategy:**

| Aspect | Strategy |
| :--- | :--- |
| **Semantic Versioning** | Each bundle release is tagged with SemVer (e.g., `v1.2.0`). Breaking changes increment the major version. |
| **Immutable Tags** | Once published, a versioned bundle is immutable. Fixes are released as new versions. |
| **Rollback** | The Policy Engine can pin to a specific bundle version per tenant. Rolling back is a configuration change, not a code deployment. |
| **Signature Verification** | Bundles are signed with `cosign`. The Policy Engine verifies the signature before loading a new bundle revision. |

### 2.4 OPA Input Document Structure

The Policy Engine constructs a standardized input document before calling OPA. This ensures every Rego policy receives a consistent, predictable schema.

```json
{
  "pipeline": {
    "pipeline_id": "run-84920",
    "project_id": "proj-core-api",
    "repository": "https://github.com/acme/core-api",
    "branch": "main",
    "commit_sha": "7a3b4c9d1e...",
    "trigger_actor": "jane.doe",
    "ci_tool": "github_actions"
  },
  "scan_results": {
    "scan_types_completed": ["SAST", "SCA", "CONTAINER_SCAN", "SECRETS"],
    "findings": [
      {
        "finding_id": "f-001",
        "scanner_type": "SCA",
        "severity": "CRITICAL",
        "vulnerability_id": "CVE-2023-44487",
        "package": "golang.org/x/net",
        "version": "0.15.0",
        "fixed_version": "0.17.0",
        "file": "go.mod",
        "cwe_id": "CWE-400",
        "cvss_score": 7.5
      }
    ],
    "dependencies": [
      {
        "name": "express",
        "version": "4.18.2",
        "license": "MIT",
        "ecosystem": "npm"
      },
      {
        "name": "some-gpl-lib",
        "version": "2.0.0",
        "license": "GPL-3.0",
        "ecosystem": "npm"
      }
    ],
    "container": {
      "image": "docker.io/library/node:18-alpine",
      "base_image": "docker.io/library/node",
      "tag": "18-alpine",
      "registry": "docker.io"
    }
  },
  "tenant_config": {
    "tenant_id": "tenant-acme-corp",
    "severity_thresholds": {
      "fail_on": ["CRITICAL"],
      "warn_on": ["HIGH"]
    },
    "waivers": [
      {
        "waiver_id": "waiver-001",
        "vulnerability_id": "CVE-2022-12345",
        "expires_at": "2026-09-01T00:00:00Z",
        "approved_by": "ciso@acme.com",
        "reason": "Mitigated by WAF rule; patch scheduled for Q4"
      }
    ]
  }
}
```

### 2.5 OPA Decision Document Structure

Every policy must return a decision document conforming to this schema:

```json
{
  "allow": false,
  "verdict": "FAIL",
  "violations": [
    {
      "finding_id": "f-001",
      "severity": "CRITICAL",
      "message": "CRITICAL vulnerability CVE-2023-44487 in golang.org/x/net@0.15.0 -- fix available: 0.17.0",
      "remediation": "Upgrade golang.org/x/net to >= 0.17.0"
    }
  ],
  "metadata": {
    "policy_name": "Critical Vulnerability Gate",
    "policy_version": "1.2.0",
    "evaluated_at": "2026-08-09T17:15:31Z"
  }
}
```

| Field | Type | Description |
| :--- | :--- | :--- |
| `allow` | `boolean` | `true` if the policy passes, `false` if it fails. |
| `verdict` | `string` | One of `PASS`, `FAIL`, `WARN`. |
| `violations` | `array` | List of specific findings that triggered the violation. Empty if `allow` is `true`. |
| `violations[].finding_id` | `string` | Back-reference to the finding in the input document. |
| `violations[].message` | `string` | Human-readable violation description. |
| `violations[].remediation` | `string` | Suggested fix for the violation. |
| `metadata` | `object` | Policy metadata for audit logging. |

---

## 3. Example Rego Policies

### 3.1 Critical Vulnerability Gate

> **Purpose:** Fail the pipeline if **any** finding has `CRITICAL` severity, unless the specific CVE has an active, unexpired waiver.

```rego
package devsecops.vulnerability_gate

import future.keywords.in
import future.keywords.contains
import future.keywords.if
import future.keywords.every

default allow := true

# ---------------------------------------------------------------
# Collect all active, unexpired waiver CVE IDs
# ---------------------------------------------------------------
active_waiver_cves[cve] if {
    some waiver in input.tenant_config.waivers
    waiver.vulnerability_id == cve
    time.parse_rfc3339_ns(waiver.expires_at) > time.now_ns()
}

# ---------------------------------------------------------------
# Identify CRITICAL findings that are NOT waived
# ---------------------------------------------------------------
critical_findings_not_waived[violation] if {
    some finding in input.scan_results.findings
    finding.severity == "CRITICAL"
    not active_waiver_cves[finding.vulnerability_id]
    violation := {
        "finding_id": finding.finding_id,
        "severity": finding.severity,
        "message": sprintf(
            "CRITICAL vulnerability %s in %s@%s -- fix available: %s",
            [finding.vulnerability_id, finding.package,
             finding.version, finding.fixed_version]
        ),
        "remediation": sprintf(
            "Upgrade %s to >= %s",
            [finding.package, finding.fixed_version]
        ),
    }
}

# ---------------------------------------------------------------
# Gate: deny if any un-waived CRITICAL finding exists
# ---------------------------------------------------------------
allow := false if {
    count(critical_findings_not_waived) > 0
}

verdict := "FAIL" if { not allow }
verdict := "PASS" if { allow }

violations := critical_findings_not_waived

metadata := {
    "policy_name": "Critical Vulnerability Gate",
    "policy_version": "1.2.0",
}
```

---

### 3.2 License Compliance Gate

> **Purpose:** Fail the pipeline if any direct dependency uses a license on the organization's banned list (e.g., `GPL-3.0`, `AGPL-3.0`).

```rego
package devsecops.license_compliance

import future.keywords.in
import future.keywords.contains
import future.keywords.if

default allow := true

# ---------------------------------------------------------------
# Banned licenses -- loaded from data/ or inline
# ---------------------------------------------------------------
banned_licenses := {
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "SSPL-1.0",
    "EUPL-1.2",
}

# ---------------------------------------------------------------
# Find dependencies with banned licenses
# ---------------------------------------------------------------
banned_dependency_violations[violation] if {
    some dep in input.scan_results.dependencies
    dep.license in banned_licenses
    violation := {
        "finding_id": sprintf("license-%s-%s", [dep.name, dep.version]),
        "severity": "HIGH",
        "message": sprintf(
            "Dependency %s@%s uses banned license: %s (ecosystem: %s)",
            [dep.name, dep.version, dep.license, dep.ecosystem]
        ),
        "remediation": sprintf(
            "Replace %s with an alternative package using a permissive license (MIT, Apache-2.0, BSD)",
            [dep.name]
        ),
    }
}

# ---------------------------------------------------------------
# Gate
# ---------------------------------------------------------------
allow := false if {
    count(banned_dependency_violations) > 0
}

verdict := "FAIL" if { not allow }
verdict := "PASS" if { allow }

violations := banned_dependency_violations

metadata := {
    "policy_name": "License Compliance Gate",
    "policy_version": "1.0.0",
}
```

---

### 3.3 Secrets Detection Gate

> **Purpose:** Fail the pipeline if **any** secret (API key, token, password, private key) is detected in the source code. No waivers are permitted for leaked secrets -- this is a hard gate.

```rego
package devsecops.secrets_gate

import future.keywords.in
import future.keywords.contains
import future.keywords.if

default allow := true

# ---------------------------------------------------------------
# Critical secret rule IDs that are always hard-fail (no waiver)
# ---------------------------------------------------------------
hard_fail_categories := {
    "private-key",
    "aws-access-key",
    "aws-secret-key",
    "gcp-service-account",
    "github-token",
    "generic-api-key",
    "slack-webhook",
    "database-connection-string",
    "jwt-secret",
    "stripe-api-key",
}

# ---------------------------------------------------------------
# Find secrets findings from any SECRETS scanner
# ---------------------------------------------------------------
secret_violations[violation] if {
    some finding in input.scan_results.findings
    finding.scanner_type == "SECRETS"

    violation := {
        "finding_id": finding.finding_id,
        "severity": "CRITICAL",
        "message": sprintf(
            "Secret detected -- rule: %s in file %s:%d. Credential has been REDACTED.",
            [finding.rule_id, finding.file, finding.line]
        ),
        "remediation": concat(" ", [
            "1. Immediately rotate the exposed credential.",
            "2. Remove the secret from source code.",
            "3. Use a secrets manager (Vault, AWS Secrets Manager).",
            "4. Add the file pattern to .gitignore and scanner allowlist if false positive.",
        ]),
    }
}

# ---------------------------------------------------------------
# Gate -- hard fail, no waivers allowed for secrets
# ---------------------------------------------------------------
allow := false if {
    count(secret_violations) > 0
}

verdict := "FAIL" if { not allow }
verdict := "PASS" if { allow }

violations := secret_violations

metadata := {
    "policy_name": "Secrets Detection Gate",
    "policy_version": "1.0.0",
}
```

---

### 3.4 Container Image Policy

> **Purpose:** Fail the pipeline if the container base image is pulled from a registry not on the organization's approved list. This enforces supply-chain security by ensuring only vetted, internally-mirrored images are used.

```rego
package devsecops.container_image_policy

import future.keywords.in
import future.keywords.contains
import future.keywords.if

default allow := true

# ---------------------------------------------------------------
# Approved registries -- only images from these registries are
# permitted in production builds.
# ---------------------------------------------------------------
approved_registries := {
    "gcr.io/acme-approved",
    "us-docker.pkg.dev/acme-prod/base-images",
    "123456789.dkr.ecr.us-east-1.amazonaws.com/acme",
    "registry.internal.acme.com",
}

# ---------------------------------------------------------------
# Check if the container image registry is approved
# ---------------------------------------------------------------
image_registry := input.scan_results.container.registry

registry_approved if {
    some approved in approved_registries
    startswith(input.scan_results.container.image, approved)
}

# ---------------------------------------------------------------
# Build violation if registry is NOT approved
# ---------------------------------------------------------------
registry_violations[violation] if {
    not registry_approved
    violation := {
        "finding_id": "container-registry-violation",
        "severity": "HIGH",
        "message": sprintf(
            "Container image '%s' is from unapproved registry '%s'. Approved registries: %s",
            [
                input.scan_results.container.image,
                image_registry,
                concat(", ", approved_registries),
            ]
        ),
        "remediation": concat(" ", [
            "Use a base image from an approved internal registry.",
            "To add a new registry to the approved list,",
            "submit a request via the Security Governance portal.",
        ]),
    }
}

# ---------------------------------------------------------------
# Also fail if using the mutable 'latest' tag
# ---------------------------------------------------------------
mutable_tag_violations[violation] if {
    tag := input.scan_results.container.tag
    tag == "latest"
    violation := {
        "finding_id": "container-mutable-tag",
        "severity": "MEDIUM",
        "message": sprintf(
            "Container image '%s' uses mutable tag 'latest'. Pin to a specific version or SHA digest.",
            [input.scan_results.container.image]
        ),
        "remediation": "Pin the image to a specific semver tag (e.g., node:18.17.1-alpine) or a SHA256 digest.",
    }
}

# ---------------------------------------------------------------
# Combine all violations
# ---------------------------------------------------------------
all_violations := registry_violations | mutable_tag_violations

allow := false if {
    count(all_violations) > 0
}

verdict := "FAIL" if { count(registry_violations) > 0 }
verdict := "WARN" if { count(registry_violations) == 0; count(mutable_tag_violations) > 0 }
verdict := "PASS" if { count(all_violations) == 0 }

violations := all_violations

metadata := {
    "policy_name": "Container Image Policy",
    "policy_version": "1.1.0",
}
```

---

## 4. Policy Evaluation Flow

The following flowchart describes the complete decision tree from receiving a scan result event to publishing the final pipeline verdict.

```mermaid
flowchart TD
    A["Receive scan-results.aggregated event from Kafka"] --> B{"Validate event schema"}
    B -->|Invalid| B_ERR["Publish to dead-letter topic scan-results.dlq"]
    B -->|Valid| C["Extract tenant_id, project_id"]

    C --> D{"Tenant policies cached in Redis?"}
    D -->|Yes| E["Load PolicySet from Redis"]
    D -->|No| F["Query PostgreSQL for active policies"]
    F --> G["Cache PolicySet in Redis with TTL 60s"]
    G --> E

    E --> H{"PolicySet empty?"}
    H -->|Yes| H_DEFAULT["Apply organization-wide default policies"]
    H -->|No| I["PolicySet ready"]
    H_DEFAULT --> I

    I --> J["Initialize verdict_results = empty list"]
    J --> K["For Each Policy in PolicySet"]

    K --> L["Construct OPA Input Document"]
    L --> M["Call OPA Evaluator with rego.Eval"]
    M --> N{"OPA evaluation succeeded?"}
    N -->|Error| N_ERR["Log error, record policy as EVAL_ERROR, continue to next policy"]
    N -->|Success| O["Parse DecisionDocument"]

    O --> P["Append policy_id, verdict, violations to verdict_results"]
    N_ERR --> P
    P --> Q{"More policies to evaluate?"}
    Q -->|Yes| K
    Q -->|No| R["Aggregate Verdicts"]

    R --> S{"Any policy verdict == FAIL?"}
    S -->|Yes| T["Overall Verdict = FAILED"]
    S -->|No| U{"Any policy verdict == WARN?"}
    U -->|Yes| V["Overall Verdict = WARN"]
    U -->|No| W["Overall Verdict = PASSED"]

    T --> X["Write audit record to PostgreSQL"]
    V --> X
    W --> X

    X --> Y["Publish PipelineVerdict to pipeline.verdicts Kafka topic"]
    Y --> Z1["Alerting Service consumes verdict"]
    Y --> Z2["CI/CD Callback Handler consumes verdict"]
```

---

## 5. CI/CD Feedback Loop

### 5.1 Overview

The **CI/CD Callback Handler** is a dedicated microservice (or a module within the Policy Engine) that consumes `PipelineVerdict` events and translates them into platform-specific API calls to update the originating CI/CD system with pass/fail status.

### 5.2 Supported CI/CD Integrations

#### GitHub -- Checks API

| Aspect | Detail |
| :--- | :--- |
| **API** | `PATCH https://api.github.com/repos/{owner}/{repo}/check-runs/{check_run_id}` |
| **Auth** | GitHub App Installation Token (stored as encrypted credential per tenant) |
| **Status Mapping** | `PASSED` maps to `conclusion: success` / `FAILED` maps to `conclusion: failure` / `WARN` maps to `conclusion: neutral` |
| **Rich Output** | Violations are formatted as GitHub Check Run annotations, pinned to specific files and line numbers. |

#### GitLab -- Commit Status API

| Aspect | Detail |
| :--- | :--- |
| **API** | `POST https://gitlab.com/api/v4/projects/{id}/statuses/{sha}` |
| **Auth** | Project Access Token with `api` scope |
| **Status Mapping** | `PASSED` maps to `state: success` / `FAILED` maps to `state: failed` / `WARN` maps to `state: success` (with warning description) |
| **Context** | `name: "DevSecOps Policy Gate"` with `target_url` pointing to the platform's pipeline detail page. |

#### Jenkins -- Callback URL

| Aspect | Detail |
| :--- | :--- |
| **API** | `POST {callback_url}` -- Jenkins Shared Library registers a webhook URL when initiating the scan. |
| **Auth** | HMAC-SHA256 signed payload using a shared secret. |
| **Payload** | `{ "pipeline_id": "...", "verdict": "FAILED", "details_url": "..." }` |
| **Behavior** | The Jenkins Shared Library step polls `GET /api/v1/events/pipeline/{id}/status` until the verdict is available, then sets the build result accordingly. |

### 5.3 Feedback Loop Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant PE as Policy Engine
    participant Kafka as Kafka pipeline.verdicts
    participant CBH as CI/CD Callback Handler
    participant GH as GitHub API
    participant GL as GitLab API
    participant JK as Jenkins

    PE->>Kafka: Publish PipelineVerdict event

    Kafka->>CBH: Consume PipelineVerdict
    CBH->>CBH: Extract ci_tool and callback_url

    alt ci_tool == github_actions
        CBH->>GH: PATCH /repos/{owner}/{repo}/check-runs/{id} with conclusion: failure, output: violations
        GH-->>CBH: 200 OK
        Note right of GH: Commit status updated. PR shows check failure.
    else ci_tool == gitlab_ci
        CBH->>GL: POST /projects/{id}/statuses/{sha} with state: failed, description: 2 policy violations
        GL-->>CBH: 201 Created
        Note right of GL: Pipeline status updated. MR shows external status.
    else ci_tool == jenkins
        CBH->>JK: POST {callback_url} HMAC-signed payload with verdict=FAILED
        JK-->>CBH: 200 OK
        Note right of JK: Build marked UNSTABLE/FAILURE via Shared Library.
    end

    CBH->>CBH: Log callback result for audit
```

### 5.4 Retry and Failure Handling

| Scenario | Handling |
| :--- | :--- |
| **CI/CD API temporarily unavailable** | Exponential backoff retry: 1s, 2s, 4s, 8s, 16s. Max 5 retries. |
| **CI/CD API returns 4xx** | Log error, publish to `callback.failures` DLQ topic. Alert on-call team. |
| **Callback URL missing from event** | Fallback to polling mode -- CI/CD plugin polls `GET /api/v1/events/pipeline/{id}/status`. |
| **Verdict not delivered within timeout** | CI/CD plugins implement a configurable timeout (default 10 minutes). If no verdict arrives, the pipeline step fails with a `TIMEOUT` status. |

---

## 6. Governance & Audit

### 6.1 Audit Logging

Every policy evaluation produces an **immutable audit record** stored in PostgreSQL and indexed in Elasticsearch.

**PostgreSQL Schema: `policy_evaluations`**

```sql
CREATE TABLE policy_evaluations (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pipeline_id       TEXT NOT NULL,
    tenant_id         TEXT NOT NULL,
    project_id        TEXT NOT NULL,
    commit_sha        TEXT NOT NULL,
    branch            TEXT NOT NULL,
    trigger_actor     TEXT NOT NULL,

    -- Verdict
    overall_verdict   TEXT NOT NULL CHECK (overall_verdict IN ('PASSED', 'FAILED', 'WARN')),
    policy_results    JSONB NOT NULL,         -- Full array of per-policy verdicts & violations
    input_document    JSONB NOT NULL,         -- Complete OPA input (for reproducibility)

    -- Policy bundle metadata
    bundle_version    TEXT NOT NULL,          -- e.g., "v1.2.0"
    bundle_digest     TEXT NOT NULL,          -- SHA256 of the loaded bundle

    -- Timing
    evaluated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    evaluation_ms     INTEGER NOT NULL,       -- Wall-clock time for full evaluation

    -- Indexing
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for common query patterns
CREATE INDEX idx_pe_tenant_project ON policy_evaluations (tenant_id, project_id);
CREATE INDEX idx_pe_pipeline ON policy_evaluations (pipeline_id);
CREATE INDEX idx_pe_verdict ON policy_evaluations (overall_verdict);
CREATE INDEX idx_pe_created_at ON policy_evaluations (created_at DESC);
CREATE INDEX idx_pe_actor ON policy_evaluations (trigger_actor);
```

> [!IMPORTANT]
> The `input_document` column stores the complete OPA input. This enables **full reproducibility** -- any past evaluation can be replayed against a specific bundle version to verify the decision.

### 6.2 Policy Versioning & Change Tracking

**PostgreSQL Schema: `policy_versions`**

```sql
CREATE TABLE policy_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id       TEXT NOT NULL,
    version         TEXT NOT NULL,            -- SemVer: "1.2.0"
    rego_source     TEXT NOT NULL,            -- Full Rego source code
    checksum        TEXT NOT NULL,            -- SHA256 of the Rego source
    change_summary  TEXT,                     -- Human description of what changed
    author          TEXT NOT NULL,            -- Who authored the change
    approved_by     TEXT,                     -- Who approved (4-eyes review)
    git_commit_sha  TEXT NOT NULL,            -- Commit in the policies-repo
    status          TEXT NOT NULL DEFAULT 'ACTIVE'
                    CHECK (status IN ('ACTIVE', 'DEPRECATED', 'DRAFT')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (policy_id, version)
);
```

**Change Tracking Workflow:**

1. **Author** creates a branch in the `policies-repo`, writes/updates Rego and tests.
2. **CI Pipeline** runs `opa fmt --check`, `opa check`, and `opa test ./...` -- all must pass.
3. **Peer Review** -- a second security engineer reviews the PR (enforced via CODEOWNERS).
4. **Merge to main** triggers the bundle build pipeline, producing a versioned bundle pushed to the OCI registry.
5. **Policy Engine pods** detect the new bundle within 30 seconds and hot-reload.
6. **Audit trail** -- the `policy_versions` table records who authored, who approved, and which git commit produced the new version.

### 6.3 Exception / Waiver Workflow

The waiver system allows teams to request temporary policy bypasses for specific findings that have mitigating controls or planned remediation.

```mermaid
flowchart TD
    A["Developer: I need a waiver for CVE-2022-12345"] --> B["Submit waiver request via Web UI / API"]
    B --> C["Waiver Request Created with status: PENDING_APPROVAL"]

    C --> D{"Auto-approve eligible? MEDIUM severity, fix ETA under 30 days"}
    D -->|Yes| E["Auto-approved by system, status: APPROVED"]
    D -->|No| F["Route to Security Team for manual review"]

    F --> G{"Security Team Decision"}
    G -->|Approved| H["status: APPROVED, set expiration date"]
    G -->|Rejected| I["status: REJECTED, provide rejection reason"]

    H --> J["Waiver stored in PostgreSQL waivers table"]
    E --> J
    J --> K["Waiver included in tenant_config.waivers for OPA input"]

    K --> L["Policy Engine skips waived finding during next evaluation"]

    L --> M{"Waiver expired?"}
    M -->|Yes| N["Finding enforced again in next pipeline run"]
    M -->|No| O["Finding remains waived"]

    I --> P["Developer must remediate or re-request with additional justification"]
```

**PostgreSQL Schema: `waivers`**

```sql
CREATE TABLE waivers (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         TEXT NOT NULL,
    project_id        TEXT NOT NULL,
    waiver_type       TEXT NOT NULL CHECK (waiver_type IN ('CVE', 'LICENSE', 'POLICY')),

    -- What is being waived
    vulnerability_id  TEXT,                   -- e.g., "CVE-2022-12345" (for CVE waivers)
    policy_id         TEXT,                   -- e.g., "pol-license-compliance" (for policy waivers)
    package_name      TEXT,                   -- e.g., "some-gpl-lib" (for license waivers)

    -- Justification
    reason            TEXT NOT NULL,
    mitigating_controls TEXT,                 -- e.g., "WAF rule deployed", "Not reachable in prod"
    remediation_plan  TEXT,                   -- e.g., "Patch scheduled for sprint 47"

    -- Approval chain
    requested_by      TEXT NOT NULL,
    approved_by       TEXT,
    status            TEXT NOT NULL DEFAULT 'PENDING_APPROVAL'
                      CHECK (status IN (
                          'PENDING_APPROVAL', 'APPROVED', 'REJECTED',
                          'EXPIRED', 'REVOKED'
                      )),

    -- Lifecycle
    requested_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_at       TIMESTAMPTZ,
    expires_at        TIMESTAMPTZ NOT NULL,   -- Hard expiration, max 90 days
    revoked_at        TIMESTAMPTZ,
    revoked_by        TEXT,
    revoke_reason     TEXT,

    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Ensure fast lookups during policy evaluation
CREATE INDEX idx_waivers_tenant_project ON waivers (tenant_id, project_id, status);
CREATE INDEX idx_waivers_vuln ON waivers (vulnerability_id) WHERE status = 'APPROVED';
CREATE INDEX idx_waivers_expiry ON waivers (expires_at) WHERE status = 'APPROVED';
```

### 6.4 Compliance Reporting

| Report | Frequency | Audience | Content |
| :--- | :--- | :--- | :--- |
| **Policy Evaluation Summary** | Real-time (per pipeline) | Developers, DevOps | Per-pipeline pass/fail with violation details and remediation links. |
| **Tenant Compliance Posture** | Daily digest | Engineering Managers | Pass rate trends, top recurring violations, MTTR for policy failures. |
| **Waiver Inventory** | Weekly | CISO, Security Team | All active waivers, approaching expirations, auto-approved vs. manually approved breakdown. |
| **Policy Change Audit Log** | On-demand | Compliance Auditors | Full history of policy changes: who changed what, when, and who approved. Linked to git commits. |
| **SOC 2 / ISO 27001 Evidence** | Quarterly | External Auditors | Exported evaluation records demonstrating continuous policy enforcement across all pipelines. |

> [!TIP]
> All reports are available via the **Reporting & Analytics Service** API and rendered in the **Frontend Dashboard**. Raw data can also be exported as CSV/PDF for external audit submissions.

---

*End of Policy Engine & OPA Integration Design Document.*
