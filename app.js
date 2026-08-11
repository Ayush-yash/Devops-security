// -------------------------------------------------------------
// ShieldOps Application Script — Backend-Integrated Dashboard Engine
// -------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
    // API Server configuration
    const API_BASE = "http://localhost:8080/api/v1";

    let state = {
        blockedCount: 0,
        totalVulns: 0,
        vulnerabilities: [],
        pipelines: [],
        alerts: [],
        activeTab: "dashboard",
        currentVulnerabilityFilter: "all",
        currentScannerFilter: "all",
        policies: {
            criticalBlock: true,
            secretsBlock: true,
            licenseBlock: true,
            registryBlock: false,
            slackIntegration: true,
            jiraIntegration: true
        },
        userRole: "SECURITY_LEAD" // Default RBAC Role
    };

    // -------------------------------------------------------------
    // Data Sync Interface (API Fetch Client)
    // -------------------------------------------------------------
    async function syncData() {
        try {
            const [vulnsRes, pipelinesRes, alertsRes, policiesRes, statsRes] = await Promise.all([
                fetch(`${API_BASE}/findings`),
                fetch(`${API_BASE}/pipelines`),
                fetch(`${API_BASE}/alerts`),
                fetch(`${API_BASE}/policies`),
                fetch(`${API_BASE}/dashboard/stats`)
            ]);

            state.vulnerabilities = await vulnsRes.json();
            state.pipelines = await pipelinesRes.json();
            state.alerts = await alertsRes.json();
            state.policies = await policiesRes.json();
            state.dashboardStats = await statsRes.json();

            updateDashboardUI();
            renderVulnerabilityTable();
            renderAlertFeed();
            renderPipelineList();
            syncPolicyToggles();
            updateRegoPreview();
            enforceRBAC();
            
            if (state.activeTab === "dashboard") {
                renderTrendsChart();
            }
        } catch (error) {
            console.error("Error syncing dashboard state from API:", error);
        }
    }

    function updateDashboardUI() {
        if (!state.dashboardStats) return;

        const { metrics, healthScore } = state.dashboardStats;

        document.getElementById("dashboard-total-projects").innerText = metrics.projects.toLocaleString();
        document.getElementById("blocked-count").innerText = metrics.pipelines.blocked.toLocaleString();
        document.getElementById("total-vuln-count").innerText = metrics.findings.open.toLocaleString();
        
        const healthScoreEl = document.getElementById("dashboard-health-score");
        healthScoreEl.innerText = healthScore;
        
        // Update health score color based on value
        const footer = document.getElementById("health-score-footer");
        if (healthScore >= 90) {
            healthScoreEl.style.color = "var(--success)";
            footer.className = "stat-footer text-success";
        } else if (healthScore >= 70) {
            healthScoreEl.style.color = "var(--warning)";
            footer.className = "stat-footer text-warning";
        } else {
            healthScoreEl.style.color = "var(--danger)";
            footer.className = "stat-footer text-danger";
        }
    }

    // Auto-refresh stats loop every 1.5 seconds to capture pipeline run progression
    setInterval(syncData, 1500);

    // -------------------------------------------------------------
    // RBAC Enforcement Rules
    // -------------------------------------------------------------
    const roleSelect = document.getElementById("select-user-role");
    const userAvatar = document.getElementById("user-avatar");

    function enforceRBAC() {
        const role = state.userRole;
        
        // Update avatar label
        if (role === "SECURITY_LEAD") userAvatar.innerText = "JD";
        else if (role === "ADMIN") userAvatar.innerText = "AD";
        else if (role === "DEVELOPER") userAvatar.innerText = "DD";
        else if (role === "VIEWER") userAvatar.innerText = "VV";

        const hasWriteAccess = (role === "ADMIN" || role === "SECURITY_LEAD");

        // Enable/Disable policy toggles based on RBAC rules
        const toggles = [
            "policy-critical-block", "policy-secrets-block", 
            "policy-license-block", "policy-registry-block",
            "policy-slack-integration", "policy-jira-integration"
        ];
        
        toggles.forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                el.disabled = !hasWriteAccess;
                // Add class for visual styling
                el.parentElement.style.opacity = hasWriteAccess ? "1" : "0.5";
            }
        });
    }

    async function loadSettings() {
        try {
            const res = await fetch(`${API_BASE}/policies`);
            const policies = await res.json();
    
            document.getElementById('policy-critical-block').checked = policies.criticalBlock === true;
            document.getElementById('policy-secrets-block').checked = policies.secretsBlock === true;
            document.getElementById('policy-registry-block').checked = policies.registryBlock === true;
            
            document.getElementById('policy-slack-integration').checked = policies.slackIntegration === true;
            document.getElementById('policy-jira-integration').checked = policies.jiraIntegration === true;
            
            // Load email integration (default false if not set in DB yet)
            document.getElementById('policy-email-integration').checked = policies.emailIntegration === true;
    
            // Check Integration configuration status
            const statusRes = await fetch(`${API_BASE}/integrations/status`);
            const integrationStatus = await statusRes.json();
            
            const updateBadge = (id, configured) => {
                const badge = document.getElementById(id);
                if (badge) {
                    if (configured) {
                        badge.textContent = 'Configured';
                        badge.className = 'badge badge-info';
                    } else {
                        badge.textContent = 'Not Configured';
                        badge.className = 'badge badge-warning';
                    }
                }
            };
            
            updateBadge('badge-slack-status', integrationStatus.slack.configured);
            updateBadge('badge-jira-status', integrationStatus.jira.configured);
            updateBadge('badge-email-status', integrationStatus.email.configured);
    
        } catch (err) {
            console.error("Failed to load settings:", err);
        }
    }

    roleSelect.value = state.userRole;
    roleSelect.addEventListener("change", async (e) => {
        state.userRole = e.target.value;
        enforceRBAC();
        
        try {
            await fetch(`${API_BASE}/users/role`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-User-Role": state.userRole
                },
                body: JSON.stringify({ role: state.userRole })
            });
        } catch (err) {
            console.error("Failed to persist role change in database:", err);
        }

        // Push notification alert
        state.alerts.unshift({
            id: Date.now(),
            type: "info",
            title: "RBAC Role Switched",
            desc: `User session swapped to ${state.userRole}. Gating edits will update.`,
            time: "Just now"
        });
        renderAlertFeed();
    });

    // -------------------------------------------------------------
    // Navigation / Tab Routing System
    // -------------------------------------------------------------
    const navButtons = document.querySelectorAll(".nav-btn");
    const tabContents = document.querySelectorAll(".tab-content");
    const pageTitle = document.getElementById("page-title");
    const pageSubtitle = document.getElementById("page-subtitle");

    const tabSubtitles = {
        dashboard: "Security metrics across 500+ active pipelines",
        pipelines: "Real-time state and status logs of running scanners",
        vulnerabilities: "Vulnerability aggregation database, details, and remediation dashboard",
        policies: "Manage organization compliance gates and Open Policy Agent definitions",
        integrations: "Developer setup documentation for CI/CD runners"
    };

    navButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetTab = btn.getAttribute("data-tab");
            
            navButtons.forEach(b => b.classList.remove("active"));
            tabContents.forEach(c => c.classList.remove("active"));
            
            btn.classList.add("active");
            document.getElementById(`tab-${targetTab}`).classList.add("active");
            
            pageTitle.innerText = btn.innerText;
            pageSubtitle.innerText = tabSubtitles[targetTab];
            state.activeTab = targetTab;
            
            if (targetTab === "dashboard") {
                renderTrendsChart(); // Re-render chart sizing on show
            }
        });
    });

    // -------------------------------------------------------------
    // Chart.js Configuration for Vulnerability Trends
    // -------------------------------------------------------------
    let chartInstance = null;
    function renderTrendsChart() {
        if (!state.dashboardStats || !state.dashboardStats.trends) return;
        
        const trends = state.dashboardStats.trends;
        const ctx = document.getElementById('trendsChart').getContext('2d');
        if (chartInstance) {
            chartInstance.destroy();
        }

        chartInstance = new Chart(ctx, {
            type: 'line',
            data: {
                labels: trends.labels,
                datasets: [
                    {
                        label: 'Critical',
                        data: trends.datasets.critical,
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2
                    },
                    {
                        label: 'High',
                        data: trends.datasets.high,
                        borderColor: '#f59e0b',
                        backgroundColor: 'rgba(245, 158, 11, 0.1)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2
                    },
                    {
                        label: 'Medium',
                        data: trends.datasets.medium,
                        borderColor: '#06b6d4',
                        backgroundColor: 'rgba(6, 182, 212, 0.05)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: '#9ca3af',
                            font: { family: 'Plus Jakarta Sans', weight: '600' }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#9ca3af' }
                    },
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#9ca3af' }
                    }
                }
            }
        });
    }

    // -------------------------------------------------------------
    // Render Vulnerability List
    // -------------------------------------------------------------
    const vulnerabilitiesTbody = document.getElementById("vulnerabilities-tbody");
    
    function renderVulnerabilityTable() {
        vulnerabilitiesTbody.innerHTML = "";
        
        let filtered = state.vulnerabilities.filter(v => {
            const matchesSev = state.currentVulnerabilityFilter === "all" || v.severity === state.currentVulnerabilityFilter;
            const matchesScan = state.currentScannerFilter === "all" || v.scanner === state.currentScannerFilter;
            return matchesSev && matchesScan;
        });

        if (filtered.length === 0) {
            vulnerabilitiesTbody.innerHTML = `<tr><td colspan="7" class="text-secondary" style="text-align:center; padding: 2rem;">No vulnerabilities found matching filters.</td></tr>`;
            return;
        }

        filtered.forEach(v => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><span class="vuln-severity-badge ${v.severity.toLowerCase()}">${v.severity}</span></td>
                <td>
                    <div class="vuln-title-cell">
                        <span class="cve-id">${v.cve}</span>
                        <span class="text-secondary">${v.title}</span>
                    </div>
                </td>
                <td><span class="badge badge-info">${v.scannerName}</span></td>
                <td><strong>${v.project}</strong></td>
                <td class="text-secondary"><code>${v.file}:${v.line}</code></td>
                <td>
                    <span class="badge ${v.status === 'OPEN' ? 'badge-failed' : ((v.status === 'WAIVED' || v.status === 'IGNORED') ? 'badge-warning' : 'badge-passed')}">${v.status}</span>
                    ${v.waiverStatus === 'PENDING' ? '<span class="badge badge-warning" style="margin-left: 0.5rem; font-size: 0.65rem; padding: 0.15rem 0.4rem;">PENDING</span>' : ''}
                </td>
                <td><button class="btn btn-outline btn-sm action-inspect-btn" data-id="${v.id}">Inspect</button></td>
            `;
            vulnerabilitiesTbody.appendChild(tr);
        });

        document.querySelectorAll(".action-inspect-btn").forEach(btn => {
            btn.addEventListener("click", () => {
                const vulnId = btn.getAttribute("data-id");
                openVulnerabilityModal(vulnId);
            });
        });
    }

    const filterButtons = document.querySelectorAll(".filter-btn");
    filterButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            filterButtons.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            state.currentVulnerabilityFilter = btn.getAttribute("data-severity");
            renderVulnerabilityTable();
        });
    });

    const selectScanner = document.getElementById("select-scanner-type");
    selectScanner.addEventListener("change", (e) => {
        state.currentScannerFilter = e.target.value;
        renderVulnerabilityTable();
    });

    // -------------------------------------------------------------
    // Render Dashboard Alert Activity Feed
    // -------------------------------------------------------------
    const alertList = document.getElementById("recent-alerts-list");
    function renderAlertFeed() {
        alertList.innerHTML = "";
        state.alerts.forEach(alert => {
            const div = document.createElement("div");
            div.className = "activity-item";
            div.innerHTML = `
                <span class="activity-icon-indicator ${alert.type}"></span>
                <div class="activity-body">
                    <span class="activity-title">${alert.title}</span>
                    <span class="activity-desc">${alert.desc}</span>
                    <span class="activity-time">${alert.time}</span>
                </div>
            `;
            alertList.appendChild(div);
        });
    }

    // -------------------------------------------------------------
    // Render Live Pipeline Scan Rows
    // -------------------------------------------------------------
    const pipelinesList = document.getElementById("pipelines-list");
    function renderPipelineList() {
        pipelinesList.innerHTML = "";
        state.pipelines.forEach(pipeline => {
            const container = document.createElement("div");
            container.className = "pipeline-run-row";
            
            let scansHtml = "";
            const scanKeys = Object.keys(pipeline.scans);
            scanKeys.forEach(key => {
                const scan = pipeline.scans[key];
                let statusBadgeColor = "text-muted";
                let progressClass = "";
                
                if (scan.status === "RUNNING") {
                    statusBadgeColor = "text-info";
                    progressClass = "running";
                } else if (scan.status === "PASSED") {
                    statusBadgeColor = "text-success";
                    progressClass = "passed";
                } else if (scan.status === "FAILED") {
                    statusBadgeColor = "text-danger";
                    progressClass = "failed";
                }

                scansHtml += `
                    <div class="scan-progress-cell">
                        <div class="scan-cell-header">
                            <span>${scan.name} (${key})</span>
                            <span class="${statusBadgeColor} scan-cell-status-label">${scan.status}</span>
                        </div>
                        <div class="progress-track">
                            <div class="progress-fill ${progressClass}" style="width: ${scan.progress}%"></div>
                        </div>
                        ${scan.status === 'FAILED' ? `<span class="text-danger" style="font-size:0.75rem;">Found ${scan.count} Issue(s)</span>` : ''}
                    </div>
                `;
            });

            let ciIconPath = "";
            if (pipeline.ciSystem === "github") {
                ciIconPath = `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>`;
            } else if (pipeline.ciSystem === "gitlab") {
                ciIconPath = `<svg viewBox="0 0 24 24" fill="currentColor"><path d="m23.951 13.585-1.478-4.553a.368.368 0 0 0-.106-.178.36.36 0 0 0-.206-.067.362.362 0 0 0-.256.096.38.38 0 0 0-.106.19l-1.921 5.91H4.072l-1.92-5.91a.382.382 0 0 0-.107-.19.362.362 0 0 0-.256-.096.36.36 0 0 0-.206.067.368.368 0 0 0-.106.178L.049 13.585a.738.738 0 0 0 .073.593.753.753 0 0 0 .423.336L12 18.067l11.455-3.553a.753.753 0 0 0 .423-.336.738.738 0 0 0 .073-.593Z"/></svg>`;
            } else {
                ciIconPath = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/></svg>`;
            }

            container.innerHTML = `
                <div class="pipeline-run-header">
                    <div class="pipeline-info-meta">
                        <div class="ci-icon ${pipeline.ciSystem}">
                            ${ciIconPath}
                        </div>
                        <div class="run-details">
                            <span class="run-project-name">${pipeline.project} <span class="text-muted" style="font-weight: 500;">(${pipeline.branch})</span></span>
                            <span class="run-meta-txt">ID: ${pipeline.id} &bull; SHA: ${pipeline.commit} &bull; Triggered by ${pipeline.trigger}</span>
                        </div>
                    </div>
                    <div class="pipeline-run-status" style="display: flex; gap: 0.5rem; align-items: center;">
                        <button class="btn btn-outline btn-sm btn-view-logs" data-pipeline-id="${pipeline.id}" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;">View Logs</button>
                        <span class="badge ${pipeline.status === 'RUNNING' ? 'badge-running' : (pipeline.status === 'PASSED' ? 'badge-passed' : 'badge-blocked')}">${pipeline.status}</span>
                    </div>
                </div>
                <div class="scanner-progress-row">
                    ${scansHtml}
                </div>
            `;
            pipelinesList.appendChild(container);
        });

        // Add event listeners to "View Logs" buttons
        document.querySelectorAll('.btn-view-logs').forEach(btn => {
            btn.addEventListener('click', (e) => {
                openLogsModal(e.target.getAttribute('data-pipeline-id'));
            });
        });
    }

    // -------------------------------------------------------------
    // Logs Modal and SSE Logic
    // -------------------------------------------------------------
    const logsModal = document.getElementById("logs-modal");
    const logsModalBody = document.getElementById("logs-modal-body");
    const logsModalTitle = document.getElementById("logs-modal-title");
    const btnCloseLogsModal = document.getElementById("btn-close-logs-modal");
    let currentEventSource = null;

    function closeLogsModal() {
        logsModal.classList.remove("open");
        if (currentEventSource) {
            currentEventSource.close();
            currentEventSource = null;
        }
    }

    btnCloseLogsModal.addEventListener("click", closeLogsModal);
    logsModal.addEventListener("click", (e) => {
        if (e.target === logsModal) closeLogsModal();
    });

    function openLogsModal(pipelineId) {
        logsModalTitle.innerText = `Logs - ${pipelineId}`;
        logsModalBody.innerHTML = `<div>Connecting to log stream...</div>`;
        logsModal.classList.add("open");
        
        if (currentEventSource) {
            currentEventSource.close();
        }

        currentEventSource = new EventSource(`${API_BASE}/pipelines/${pipelineId}/logs/stream`);
        
        currentEventSource.onmessage = (event) => {
            if (logsModalBody.innerHTML.includes("Connecting to log stream...")) {
                logsModalBody.innerHTML = ""; // Clear initial message
            }
            
            const logData = JSON.parse(event.data);
            const logEntry = document.createElement("div");
            logEntry.style.marginBottom = "0.5rem";
            logEntry.style.borderBottom = "1px solid rgba(255,255,255,0.05)";
            logEntry.style.paddingBottom = "0.25rem";
            
            let color = "#a5b4fc";
            if (logData.severity === "ERROR") color = "#ef4444";
            else if (logData.severity === "WARN") color = "#f59e0b";
            else if (logData.severity === "SUCCESS") color = "#10b981";
            
            logEntry.innerHTML = `
                <span style="color: #6b7280;">[${new Date(logData.created_at).toLocaleTimeString()}]</span>
                <span style="color: ${color}; font-weight: bold; width: 80px; display: inline-block;">[${logData.severity}]</span>
                <span style="color: #93c5fd; width: 100px; display: inline-block;">[${logData.stage}]</span>
                <span>${logData.message}</span>
            `;
            
            logsModalBody.appendChild(logEntry);
            
            // Auto scroll to bottom
            logsModalBody.scrollTop = logsModalBody.scrollHeight;
        };

        currentEventSource.onerror = (err) => {
            console.error("SSE Error:", err);
            const errEntry = document.createElement("div");
            errEntry.style.color = "#ef4444";
            errEntry.innerText = "[Connection] Lost connection to log stream or ended. Attempting to reconnect...";
            logsModalBody.appendChild(errEntry);
        };
    }

    // -------------------------------------------------------------
    // Live Pipeline Simulator Trigger via Backend Call
    // -------------------------------------------------------------
    const btnTrigger = document.getElementById("btn-trigger-pipeline");
    
    btnTrigger.addEventListener("click", async () => {
        btnTrigger.disabled = true;
        btnTrigger.innerHTML = `<svg class="icon animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg> Running scans...`;
        
        try {
            const res = await fetch(`${API_BASE}/events/pipeline/trigger`, { 
                method: "POST",
                headers: { "X-User-Role": state.userRole }
            });
            if (res.status === 403 || res.status === 401) {
                alert("RBAC Authorization Failed: Your role does not have permission to execute pipelines.");
                btnTrigger.disabled = false;
                btnTrigger.innerHTML = `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Trigger Demo Pipeline`;
                return;
            }

            const pipelinesTabBtn = document.querySelector('[data-tab="pipelines"]');
            if (pipelinesTabBtn) {
                pipelinesTabBtn.click();
            }

            await syncData();
        } catch (error) {
            console.error("Error triggering pipeline execution:", error);
        } finally {
            setTimeout(() => {
                btnTrigger.disabled = false;
                btnTrigger.innerHTML = `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Trigger Demo Pipeline`;
            }, 3000);
        }
    });

    // -------------------------------------------------------------
    // Detail Inspector Modal Handling
    // -------------------------------------------------------------
    const modal = document.getElementById("vuln-modal");
    const modalBody = document.getElementById("modal-body-content");
    const modalTitle = document.getElementById("modal-title");
    const btnCloseModal = document.getElementById("btn-close-modal");
    
    let currentInspectedId = null;

    async function handleWaiverAction(action, vulnId, reason) {
        try {
            const url = `${API_BASE}/waive/${vulnId}/${action}`;
            const body = reason ? JSON.stringify({ reason }) : undefined;
            const res = await fetch(url, {
                method: "POST",
                headers: { 
                    "X-User-Role": state.userRole,
                    "Content-Type": "application/json"
                },
                body
            });
            if (res.status === 403 || res.status === 401) {
                alert(`RBAC Authorization Failed: Your role does not have permission to ${action} waivers.`);
                return;
            }
            closeModal();
            syncData();
        } catch (error) {
            console.error(`Error executing waiver ${action}:`, error);
        }
    }    function openVulnerabilityModal(vulnId) {
        const vuln = state.vulnerabilities.find(v => v.id === vulnId);
        if (!vuln) return;
        currentInspectedId = vulnId;

        modalTitle.innerText = `${vuln.cve}: ${vuln.title}`;
        
        modalBody.innerHTML = `
            <div class="modal-metadata">
                <div class="meta-item">
                    <span>Severity</span>
                    <span class="text-${vuln.severity === 'CRITICAL' ? 'danger' : (vuln.severity === 'HIGH' ? 'warning' : 'info')}">${vuln.severity}</span>
                </div>
                <div class="meta-item">
                    <span>Scanner Engine</span>
                    <span>${vuln.scannerName} (${vuln.scanner})</span>
                </div>
                <div class="meta-item">
                    <span>Status</span>
                    <span>${vuln.status}</span>
                </div>
                <div class="meta-item">
                    <span>Rule / CVE</span>
                    <span>${vuln.ruleId || vuln.cve}</span>
                </div>
                <div class="meta-item">
                    <span>Target Project</span>
                    <span>${vuln.project}</span>
                </div>
                <div class="meta-item">
                    <span>Pipeline Run</span>
                    <span>${vuln.pipeline_id ? vuln.pipeline_id.substring(0, 8) + '...' : 'Unknown'}</span>
                </div>
                <div class="meta-item" style="grid-column: span 2;">
                    <span>File Location</span>
                    <span><code>${vuln.file}:${vuln.line}</code></span>
                </div>
            </div>
            
            ${vuln.waiverStatus ? `
            <div class="modal-metadata" style="margin-top: 1rem; border-color: var(--warning); background: rgba(245, 158, 11, 0.05); display: flex; flex-direction: column; align-items: flex-start; gap: 0.5rem; width: 100%; padding: 1rem; border: 1px solid var(--border-color); border-radius: var(--border-radius);">
                <div class="meta-item" style="width: 100%; display: flex; justify-content: space-between;">
                    <span>Waiver Status</span>
                </div>` : ''}
                <div class="meta-item" style="width: 100%; display: flex; justify-content: space-between;">
                    <span>Expires At</span>
                    <span>${new Date(vuln.waiverExpiresAt).toLocaleString()}</span>
                </div>
                <div style="width: 100%; margin-top: 0.25rem; font-size: 0.85rem; color: var(--text-secondary); border-top: 1px solid var(--border-color); padding-top: 0.5rem;">
                    <strong>Reason:</strong> ${vuln.waiverReason}
                </div>
            </div>
            ` : ''}
            
            <h4>Vulnerability Description</h4>
            <p>${vuln.description}</p>
            
            <h4>Affected Dependency Package</h4>
            <p><strong>Package:</strong> <code>${vuln.package}</code> &bull; <strong>Current Version:</strong> ${vuln.version} &bull; <strong>Fixed in Version:</strong> ${vuln.fixedVersion}</p>
            
            <h4>Recommended Remediation Steps</h4>
            <div class="code-block-remediation">
${vuln.remediation}
            </div>
            
            <h4>Audit History</h4>
            <div id="modal-history-container" style="background: rgba(255,255,255,0.02); padding: 1rem; border-radius: 4px; font-size: 0.85rem; max-height: 150px; overflow-y: auto;">
                <em>Loading history...</em>
            </div>

            ${state.userRole === "VIEWER" ? `<p class="text-danger" style="font-weight:600; margin-top: 1rem;">⚠️ RBAC Alert: Your Viewer role does not have authorization to modify vulnerabilities.</p>` : ''}
        `;

        // Fetch finding history
        fetch(`${API_BASE}/findings/${vuln.id}/history`)
            .then(res => res.json())
            .then(history => {
                const historyContainer = document.getElementById("modal-history-container");
                if (history.length === 0) {
                    historyContainer.innerHTML = `<em>No history found.</em>`;
                    return;
                }
                historyContainer.innerHTML = history.map(h => `
                    <div style="margin-bottom: 0.5rem; padding-bottom: 0.5rem; border-bottom: 1px solid rgba(255,255,255,0.05);">
                        <span style="color: var(--primary); font-weight: 600;">[${new Date(h.created_at).toLocaleString()}]</span>
                        <span style="margin-left: 0.5rem; font-weight: 600;">${h.actor} (${h.role})</span>
                        <span style="margin-left: 0.5rem; color: #a1a1aa;">${h.action}</span>
                        ${h.details && h.details.reason ? `<div style="color: #d4d4d8; margin-top: 0.25rem; font-style: italic;">Reason: ${h.details.reason}</div>` : ''}
                    </div>
                `).join('');
            })
            .catch(err => {
                const historyContainer = document.getElementById("modal-history-container");
                if (historyContainer) historyContainer.innerHTML = `<em>Error loading history.</em>`;
            });

        const isViewer = state.userRole === "VIEWER";
        const hasWriteAccess = (state.userRole === "ADMIN" || state.userRole === "SECURITY_LEAD");

        const modalFooter = document.querySelector(".modal-footer");
        modalFooter.innerHTML = "";

        const waiveBtn = document.createElement("button");
        waiveBtn.className = "btn btn-outline";
        waiveBtn.id = "btn-modal-waive";

        const remediateBtn = document.createElement("button");
        remediateBtn.className = "btn btn-primary";
        remediateBtn.id = "btn-modal-remediate";
        remediateBtn.innerText = "Apply Auto-Remediation";
        remediateBtn.disabled = isViewer;
        
        const ignoreBtn = document.createElement("button");
        ignoreBtn.className = "btn btn-outline";
        ignoreBtn.innerText = "Ignore Finding";
        ignoreBtn.disabled = isViewer;

        const reopenBtn = document.createElement("button");
        reopenBtn.className = "btn btn-outline";
        reopenBtn.innerText = "Reopen Finding";
        reopenBtn.disabled = isViewer;

        if (vuln.status === "RESOLVED" || vuln.status === "IGNORED") {
            reopenBtn.addEventListener("click", async () => {
                if (isViewer) return;
                try {
                    const res = await fetch(`${API_BASE}/findings/${vuln.id}/reopen`, {
                        method: "POST",
                        headers: { "X-User-Role": state.userRole }
                    });
                    if (res.status === 403 || res.status === 401) {
                        alert("RBAC Authorization Failed.");
                        return;
                    }
                    closeModal();
                    syncData();
                } catch (err) {
                    console.error("Error reopening finding:", err);
                }
            });
            modalFooter.appendChild(reopenBtn);
        } else if (vuln.waiverStatus === "PENDING") {
            if (hasWriteAccess) {
                waiveBtn.innerText = "Approve Waiver";
                waiveBtn.addEventListener("click", async () => {
                    await handleWaiverAction('approve', vuln.id);
                });

                const rejectBtn = document.createElement("button");
                rejectBtn.className = "btn btn-outline";
                rejectBtn.style.color = "var(--danger)";
                rejectBtn.style.borderColor = "var(--danger)";
                rejectBtn.innerText = "Reject Waiver";
                rejectBtn.addEventListener("click", async () => {
                    await handleWaiverAction('reject', vuln.id);
                });

                modalFooter.appendChild(rejectBtn);
                modalFooter.appendChild(waiveBtn);
                modalFooter.appendChild(remediateBtn);
            } else {
                waiveBtn.disabled = true;
                waiveBtn.innerText = "Waiver Pending Review";
                modalFooter.appendChild(waiveBtn);
                modalFooter.appendChild(remediateBtn);
            }
        } else {
            waiveBtn.innerText = "Request Temporary Waiver";
            waiveBtn.disabled = isViewer;
            waiveBtn.addEventListener("click", async () => {
                let reason = "Temporary bypass requested via dashboard.";
                if (state.userRole === "DEVELOPER") {
                    reason = prompt("Please enter the reason for this waiver request:") || "";
                    if (!reason.trim()) return;
                }
                await handleWaiverAction('request', vuln.id, reason);
            });
            
            ignoreBtn.addEventListener("click", async () => {
                if (isViewer) return;
                const reason = prompt("Please enter the reason for ignoring this finding:") || "";
                if (!reason.trim()) return;
                
                try {
                    const res = await fetch(`${API_BASE}/findings/${vuln.id}/ignore`, {
                        method: "POST",
                        headers: { "X-User-Role": state.userRole, "Content-Type": "application/json" },
                        body: JSON.stringify({ reason })
                    });
                    if (res.status === 403 || res.status === 401) {
                        alert("RBAC Authorization Failed.");
                        return;
                    }
                    closeModal();
                    syncData();
                } catch (err) {
                    console.error("Error ignoring finding:", err);
                }
            });

            modalFooter.appendChild(ignoreBtn);
            modalFooter.appendChild(waiveBtn);
            modalFooter.appendChild(remediateBtn);
        }

        remediateBtn.addEventListener("click", async () => {
            if (state.userRole === "VIEWER") return;
            try {
                const res = await fetch(`${API_BASE}/remediate/${vuln.id}`, { 
                    method: "POST",
                    headers: { "X-User-Role": state.userRole }
                });
                if (res.status === 403 || res.status === 401) {
                    alert("RBAC Authorization Failed: Your role does not have permission to resolve findings.");
                    return;
                }
                closeModal();
                syncData();
            } catch (error) {
                console.error("Error remediating vulnerability:", error);
            }
        });

        modal.classList.add("open");
    }

    function closeModal() {
        modal.classList.remove("open");
        currentInspectedId = null;
    }

    btnCloseModal.addEventListener("click", closeModal);
    modal.addEventListener("click", (e) => {
        if (e.target === modal) closeModal();
    });

    // -------------------------------------------------------------
    // Live Policy Toggle Engine & Rego Preview Output
    // -------------------------------------------------------------
    const criticalToggle = document.getElementById("policy-critical-block");
    const secretsToggle = document.getElementById("policy-secrets-block");
    const licenseToggle = document.getElementById("policy-license-block");
    const registryToggle = document.getElementById("policy-registry-block");
    
    // Slack and Jira Integrations selectors
    const slackToggle = document.getElementById("policy-slack-integration");
    const jiraToggle = document.getElementById("policy-jira-integration");
    const emailToggle = document.getElementById("policy-email-integration");
    
    const regoPre = document.getElementById("rego-output");

    async function saveSettings() {
        const policies = {
            criticalBlock: document.getElementById('policy-critical-block').checked,
            secretsBlock: document.getElementById('policy-secrets-block').checked,
            registryBlock: document.getElementById('policy-registry-block').checked,
            slackIntegration: document.getElementById('policy-slack-integration').checked,
            jiraIntegration: document.getElementById('policy-jira-integration').checked,
            emailIntegration: document.getElementById('policy-email-integration').checked
        };
        try {
            await fetch(`${API_BASE}/policies`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(policies)
            });
            syncData();
        } catch (err) {
            console.error("Error saving settings:", err);
        }
    }

    function syncPolicyToggles() {
        criticalToggle.checked = state.policies.criticalBlock;
        secretsToggle.checked = state.policies.secretsBlock;
        licenseToggle.checked = state.policies.licenseBlock;
        registryToggle.checked = state.policies.registryBlock;
        slackToggle.checked = state.policies.slackIntegration;
        jiraToggle.checked = state.policies.jiraIntegration;
        emailToggle.checked = state.policies.emailIntegration;

        document.getElementById("badge-slack-status").innerText = state.policies.slackIntegration ? "Active" : "Disabled";
        document.getElementById("badge-slack-status").className = `badge ${state.policies.slackIntegration ? 'badge-info' : 'badge-warning'}`;
        
        document.getElementById("badge-jira-status").innerText = state.policies.jiraIntegration ? "Active" : "Disabled";
        document.getElementById("badge-jira-status").className = `badge ${state.policies.jiraIntegration ? 'badge-info' : 'badge-warning'}`;
        
        document.getElementById("badge-email-status").innerText = state.policies.emailIntegration ? "Active" : "Disabled";
        document.getElementById("badge-email-status").className = `badge ${state.policies.emailIntegration ? 'badge-info' : 'badge-warning'}`;
        
        document.getElementById("badge-jira-status").innerText = state.policies.jiraIntegration ? "Active" : "Disabled";
        document.getElementById("badge-jira-status").className = `badge ${state.policies.jiraIntegration ? 'badge-info' : 'badge-warning'}`;
    }

    async function handlePolicyChange() {
        // Enforce RBAC block at UI event execution
        if (state.userRole === "DEVELOPER" || state.userRole === "VIEWER") {
            alert("RBAC Authorization Failed: You do not have permission to modify active OPA Policy Bundles.");
            syncPolicyToggles();
            return;
        }

        const payload = {
            criticalBlock: criticalToggle.checked,
            secretsBlock: secretsToggle.checked,
            licenseBlock: licenseToggle.checked,
            registryBlock: registryToggle.checked,
            slackIntegration: slackToggle.checked,
            jiraIntegration: jiraToggle.checked,
            emailIntegration: emailToggle.checked
        };
        try {
            const res = await fetch(`${API_BASE}/policies`, {
                method: "POST",
                headers: { 
                    "Content-Type": "application/json",
                    "X-User-Role": state.userRole
                },
                body: JSON.stringify(payload)
            });
            if (res.status === 403 || res.status === 401) {
                alert("RBAC Authorization Failed: Your role does not have permission to modify policies.");
                syncPolicyToggles();
                return;
            }
            syncData();
        } catch (error) {
            console.error("Error updating policies:", error);
        }
    }

    [criticalToggle, secretsToggle, licenseToggle, registryToggle, slackToggle, jiraToggle, emailToggle].forEach(toggle => {
        toggle.addEventListener("change", handlePolicyChange);
    });

    function updateRegoPreview() {
        const checkCritical = state.policies.criticalBlock;
        const checkSecrets = state.policies.secretsBlock;
        const checkLicense = state.policies.licenseBlock;
        const checkRegistry = state.policies.registryBlock;

        let regoCode = `package shieldops.admission

# Deny by default
default allow = false

# Gate variables dynamically rendered
deny_on_critical_vulnerabilities := ${checkCritical}
deny_on_secrets := ${checkSecrets}
deny_on_license_violations := ${checkLicense}
enforce_base_registry_validation := ${checkRegistry}

# 1. Evaluate final pipeline access policy
allow {
    count(violation) == 0
}

# 2. Policy Rule validations
violation[msg] {
    deny_on_critical_vulnerabilities
    input.findings[_].severity == "CRITICAL"
    msg := "FAIL: Pipeline blocked due to critical vulnerability gate rule."
}

violation[msg] {
    deny_on_secrets
    input.findings[_].scanner_type == "SECRETS"
    msg := "FAIL: Security Policy violation — Hardcoded secrets found."
}

violation[msg] {
    deny_on_license_violations
    banned_licenses := ["GPL-3.0", "AGPL-3.0", "SSPL-1.0"]
    input.findings[i].scanner_type == "SCA"
    input.findings[i].package_license == banned_licenses[_]
    msg := sprintf("WARN: License violation detected in package %v: %v", [
        input.findings[i].package,
        input.findings[i].package_license
    ])
}

violation[msg] {
    enforce_base_registry_validation
    input.findings[i].scanner_type == "CONTAINER_SCAN"
    not startswith(input.findings[i].image_registry, "34892019.dkr.ecr.us-east-1.amazonaws.com")
    msg := sprintf("FAIL: Container base registry %v is unapproved.", [input.findings[i].image_registry])
}`;
        regoPre.textContent = regoCode;
    }

    // -------------------------------------------------------------
    // Page Bootstrapper
    // -------------------------------------------------------------
    syncData();
    renderTrendsChart();
});
