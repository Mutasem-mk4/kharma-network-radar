// KHARMA SENTINEL - Specialized Features Module

async function startHunt(pid, name) {
    const titleEl = document.getElementById('hunt-pid-title');
    const overlay = document.getElementById('modal-overlay');
    const modal = document.getElementById('hunt-modal');
    if (titleEl) titleEl.innerText = `${name} (PID: ${pid})`;
    if (overlay) overlay.style.display = 'block';
    if (modal) modal.style.display = 'flex';

    document.getElementById('hunt-meta').innerHTML = 'Analyzing...';
    document.getElementById('hunt-heuristics').innerHTML = '';
    document.getElementById('hunt-strings').innerHTML = '';
    document.getElementById('hunt-files').innerHTML = '';

    try {
        const res = await fetch(`/api/hunt/${pid}`, {
            headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
        });
        const json = await res.json();
        if (json.status === 'success') {
            const d = json.data;
            document.getElementById('hunt-meta').innerHTML = `
                <b>Path:</b> ${d.exe || 'N/A'}<br>
                <b>Command:</b> <span style="font-family:monospace; color: #60a5fa;">${(d.cmdline || []).join(' ')}</span><br>
                <b>Created:</b> ${new Date(d.create_time * 1000).toLocaleString()}<br>
                <b>Status:</b> ${d.status} | <b>Threads:</b> ${d.num_threads}
            `;
            if (d.heuristics.length === 0) {
                document.getElementById('hunt-heuristics').innerHTML = '<div style="color: var(--accent); font-size: 0.8rem;">No suspicious patterns found.</div>';
            } else {
                document.getElementById('hunt-heuristics').innerHTML = d.heuristics.map(h => `<div class="heuristic-tag">${h}</div>`).join('');
            }
            document.getElementById('hunt-strings').innerHTML = (d.strings || []).map(s => `<div class="string-row">${s}</div>`).join('') || "No strings found.";
            document.getElementById('hunt-files').innerHTML = (d.open_files || []).join('<br>') || "Access Denied.";
            if (typeof lucide !== 'undefined') lucide.createIcons();
        } else {
            document.getElementById('hunt-meta').innerHTML = `<span style="color:var(--danger)">Error: ${json.message}</span>`;
        }
    } catch (e) {
        showToast("HUNT FAILED", "Forensic scan failed.", "danger");
    }
}

function closeHunt() {
    document.getElementById('modal-overlay').style.display = 'none';
    document.getElementById('hunt-modal').style.display = 'none';
}

async function generateSnapshot(pid) {
    const conn = allConnections.find(c => c.pid === pid);
    if (!conn) return;

    let huntData = {};
    try {
        const res = await fetch(`/api/hunt/${pid}`, {
            headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
        });
        const json = await res.json();
        if (json.status === 'success') huntData = json.data;
    } catch (e) { }

    const reportHtml = `
        <html>
        <head>
            <title>KHARMA_FORENSIC_SNAPSHOT_${pid}</title>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 40px; color: #1f2937; line-height: 1.6; }
                .header { border-bottom: 3px solid #6366f1; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }
                .logo { font-weight: 800; font-size: 1.5rem; letter-spacing: -1px; color: #6366f1; }
                .report-title { font-size: 1.2rem; color: #6b7280; text-transform: uppercase; }
                .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }
                .card { border: 1px solid #e5e7eb; border-radius: 8px; padding: 15px; background: #f9fafb; }
                .card-h { font-size: 0.75rem; font-weight: 700; color: #4b5563; text-transform: uppercase; margin-bottom: 10px; border-bottom: 1px solid #e5e7eb; padding-bottom: 5px; }
                .anomaly { color: #dc2626; font-weight: 600; margin-bottom: 4px; }
                .threat-status { padding: 10px; border-radius: 6px; font-weight: 700; text-align: center; margin-bottom: 20px; }
                .status-danger { background: #fee2e2; color: #b91c1c; border: 1px solid #fecaca; }
                .status-safe { background: #dcfce7; color: #15803d; border: 1px solid #bbf7d0; }
                pre { background: #111827; color: #10b981; padding: 15px; border-radius: 6px; font-size: 0.75rem; overflow-x: auto; white-space: pre-wrap; }
            </style>
        </head>
        <body>
            <div class="header">
                <div class="logo">${isPro ? 'KHARMA ENTERPRISE SENTINEL' : 'KHARMA PROACTIVE DEFENSE'}</div>
                <div class="report-title">${isPro ? 'OFFICIAL FORENSIC INCIDENT REPORT' : 'Forensic Incident Report'}</div>
            </div>
            <div class="threat-status ${conn.is_malware || (conn.anomalies && conn.anomalies.length > 0) ? 'status-danger' : 'status-safe'}">
                VERDICT: ${conn.is_malware ? 'MALICIOUS THREAT DETECTED' : (conn.anomalies && conn.anomalies.length > 0 ? 'ANOMALOUS BEHAVIOR DETECTED' : 'PROCESS STABLE / NO IMMEDIATE RISK')}
            </div>
            <div class="meta-grid">
                <div class="card">
                    <div class="card-h">Process Information</div>
                    <b>Name:</b> ${conn.process_name}<br><b>PID:</b> ${conn.pid}<br>
                    <b>AI Anomaly Score:</b> ${conn.ai_score} / 10.0<br>
                    <b>Behavioral Label:</b> ${conn.ai_level}<br>
                    <b>Execution Path:</b> ${huntData.exe || 'N/A'}<br>
                    <b>Command Line:</b> ${(huntData.cmdline || []).join(' ') || 'N/A'}<br>
                    <b>User Context:</b> ${huntData.username || 'System'}
                </div>
                <div class="card">
                    <div class="card-h">Network Context</div>
                    <b>Target IP:</b> ${conn.remote_address}<br>
                    <b>Geo-Location:</b> ${conn.location || 'Unknown'}<br>
                    <b>Throughput (Avg):</b> ${(conn.in_kbps + conn.out_kbps).toFixed(2)} KB/s<br>
                    <b>Shield Status:</b> ${conn.is_shielded ? 'ACTIVE FIREWALL BLOCK' : 'MONITORING'}
                </div>
            </div>
            <div class="card" style="margin-bottom: 30px;">
                <div class="card-h">Behavioral Analysis & Heuristics</div>
                ${(conn.anomalies || []).map(a => `<div class="anomaly">● [ANOMALY] ${a}</div>`).join('') || 'No behavioral anomalies detected.'}
                ${(huntData.heuristics || []).map(h => `<div class="anomaly">● [HEURISTIC] ${h}</div>`).join('')}
            </div>
            <div class="card">
                <div class="card-h">Extracted Binary Strings (Forensic Core)</div>
                <pre>${(huntData.strings || []).join('\n') || 'No forensic strings available.'}</pre>
            </div>
            <div style="margin-top: 40px; font-size: 0.7rem; color: #9ca3af; text-align: center;">
                Report generated by ${isPro ? 'Kharma Enterprise Suite [Licensed]' : 'Kharma Proactive Suite [Lite]'} on ${new Date().toLocaleString()}<br>
                Digital Signature: ${isPro ? 'SENTINEL-SIG-' + Math.random().toString(36).substring(2, 10).toUpperCase() : 'N/A'}
            </div>
            <script>window.onload = () => { setTimeout(() => window.print(), 500); };<\/script>
        </body>
        </html>
    `;
    const win = window.open('', '_blank');
    if (win) {
        win.document.write(reportHtml);
        win.document.close();
    }
}

async function bulkAction(type) {
    const ips = Array.from(window._selectedIps || []);
    if (ips.length === 0) return;

    showToast("BULK ACTION STARTED", `Processing ${ips.length} targets...`, "info");
    for (const ip of ips) {
        try {
            if (type === 'shield') {
                await fetch('/api/shield', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${SESSION_TOKEN}` },
                    body: JSON.stringify({ ip: ip })
                });
            } else {
                await fetch('/api/report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${SESSION_TOKEN}` },
                    body: JSON.stringify({ ip: ip, reason: "Bulk UI Flag" })
                });
            }
        } catch (e) { console.error(`Bulk failure for ${ip}:`, e); }
    }
    showToast("BULK ACTION COMPLETE", `Operations finalized.`, "info");
    if (typeof clearSelection === 'function') clearSelection();
    updateRadar();
    if (type === 'shield' && typeof updateBlocklist === 'function') updateBlocklist();
}

function applyProUI() {
    isPro = true;
    const label = document.getElementById('license-label');
    const ver = document.getElementById('system-ver-label');
    if (label) {
        label.innerText = (currentLang === 'AR' ? 'محترف' : 'PRO');
        label.style.color = "#fbbf24";
    }
    if (ver) {
        ver.innerText = (currentLang === 'AR' ? 'إصدار V11.0.1-PRO حماية المؤسسات' : "V11.0.1-PRO ENTERPRISE DEFENSE");
    }
    if (typeof applyTranslations === 'function') applyTranslations();
    const swarmPanel = document.getElementById('swarm-panel');
    const swarmOverlay = document.getElementById('swarm-overlay');
    if (swarmPanel) swarmPanel.style.opacity = "1";
    if (swarmOverlay) swarmOverlay.style.display = "none";
}

// --- GUARDIAN BOT MODULE ---

function toggleGuardian() {
    const panel = document.getElementById('guardian-panel');
    if (!panel) return;
    const isHidden = panel.style.display === 'none';
    panel.style.display = isHidden ? 'block' : 'none';

    if (isHidden) {
        // Load current settings when opening
        fetchSettingsToGuardian();
    }
}

async function fetchSettingsToGuardian() {
    try {
        const res = await fetch('/api/settings', {
            headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
        });
        const json = await res.json();
        if (json.status === 'success') {
            const d = json.data;
            document.getElementById('tg-token').value = d.telegram_bot_token || '';
            document.getElementById('tg-chat-id').value = d.telegram_chat_id || '';
            document.getElementById('discord-webhook').value = d.discord_webhook_url || '';
            document.getElementById('alert-threat').checked = d.alert_on_threat !== false;
            document.getElementById('alert-block').checked = d.alert_on_block !== false;
            document.getElementById('alert-dpi').checked = d.alert_on_dpi !== false;
        }
    } catch (e) {
        console.error("Failed to load Guardian settings:", e);
    }
}

async function saveGuardianSettings() {
    const data = {
        telegram_bot_token: document.getElementById('tg-token').value.trim(),
        telegram_chat_id: document.getElementById('tg-chat-id').value.trim(),
        discord_webhook_url: document.getElementById('discord-webhook').value.trim(),
        alert_on_threat: document.getElementById('alert-threat').checked,
        alert_on_block: document.getElementById('alert-block').checked,
        alert_on_dpi: document.getElementById('alert-dpi').checked
    };

    try {
        const res = await fetch('/api/settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${SESSION_TOKEN}`
            },
            body: JSON.stringify(data)
        });
        const json = await res.json();
        if (json.status === 'success') {
            showToast("SETTINGS SAVED", "Guardian Bot configuration updated.", "info");
        } else {
            showToast("SAVE FAILED", json.message, "danger");
        }
    } catch (e) {
        showToast("SAVE FAILED", "Network error while saving settings.", "danger");
    }
}

async function sendTestAlert() {
    showToast("TESTING...", "Sending test alert to configured channels...", "info");
    try {
        const res = await fetch('/api/settings/test', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
        });
        const json = await res.json();
        if (json.status === 'success') {
            showToast("TEST SENT", json.message, "info");
        } else {
            showToast("TEST FAILED", json.message, "danger");
        }
    } catch (e) {
        showToast("TEST FAILED", "Connection error during test.", "danger");
    }
}
