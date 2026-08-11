package devsecops.security_gate

import future.keywords.in
import future.keywords.if

default allow := true
default verdict := "PASS"
default reason := "All checks passed"

# Check if any secret is exposed
has_secrets if {
    some finding in input.findings
    finding.scannerType == "SECRETS"
    finding.status == "OPEN"
}

# Check if any critical vulnerability is present (and criticalBlock toggle is enabled)
has_critical if {
    input.config.criticalBlock == true
    some finding in input.findings
    finding.severity == "CRITICAL"
    finding.status == "OPEN"
}

# Count High vulnerabilities
high_count := count([finding | 
    some finding in input.findings
    finding.severity == "HIGH"
    finding.status == "OPEN"
])

# Count Medium vulnerabilities
medium_count := count([finding | 
    some finding in input.findings
    finding.severity == "MEDIUM"
    finding.status == "OPEN"
])

# Check if insecure container is present (and registryBlock config is enabled)
has_insecure_container if {
    input.config.registryBlock == true
    some finding in input.findings
    finding.scannerType == "CONTAINER"
    finding.status == "OPEN"
}

# Check if insecure IaC is present (and registryBlock/iacBlock config is enabled)
has_insecure_iac if {
    input.config.registryBlock == true
    some finding in input.findings
    finding.scannerType == "IAC"
    finding.status == "OPEN"
}

# Gather all block reasons as an array using helpers to prevent type coercion mismatch
block_reasons_secrets := [ "Exposed secrets found in code." | has_secrets ]
block_reasons_critical := [ "Critical vulnerabilities found." | has_critical ]
block_reasons_high := [ sprintf("High vulnerability threshold exceeded (%d found, limit is 3).", [high_count]) | high_count >= 3 ]
block_reasons_container := [ "Insecure container base image configuration found." | has_insecure_container ]
block_reasons_iac := [ "Insecure Infrastructure-as-Code configuration found." | has_insecure_iac ]

block_reasons := array.concat(
    block_reasons_secrets, 
    array.concat(
        block_reasons_critical, 
        array.concat(
            block_reasons_high, 
            array.concat(block_reasons_container, block_reasons_iac)
        )
    )
)

# Gather all warning reasons as an array
warn_reasons := [ sprintf("Medium vulnerability threshold exceeded (%d found, limit is 5).", [medium_count]) | medium_count >= 5 ]

# Gate results
allow := false if {
    count(block_reasons) > 0
}

verdict := "BLOCK" if {
    count(block_reasons) > 0
} else := "WARNING" if {
    count(block_reasons) == 0
    count(warn_reasons) > 0
} else := "PASS" if {
    count(block_reasons) == 0
    count(warn_reasons) == 0
}

reason := concat("; ", block_reasons) if {
    count(block_reasons) > 0
} else := concat("; ", warn_reasons) if {
    count(block_reasons) == 0
    count(warn_reasons) > 0
} else := "All security gates passed." if {
    count(block_reasons) == 0
    count(warn_reasons) == 0
}
