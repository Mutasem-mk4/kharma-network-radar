// KHARMA SENTINEL - UI Management Module

function showToast(title, message, type = 'danger') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    let icon = 'alert-circle';
    let iconColor = 'var(--text-main)';
    if (type === 'danger') { icon = 'shield-alert'; iconColor = 'var(--danger)'; }
    if (type === 'warning') { icon = 'alert-triangle'; iconColor = '#f59e0b'; }
    if (type === 'info') { icon = 'info'; iconColor = '#6366f1'; }

    toast.innerHTML = `
        <div class="toast-title">
            <i data-lucide="${icon}" style="width:16px; height:16px; color: ${iconColor};"></i> 
            ${title}
        </div>
        <div class="toast-message">${message}</div>
    `;
    container.appendChild(toast);
    if (typeof lucide !== 'undefined') lucide.createIcons({ root: toast });

    setTimeout(() => toast.classList.add('show'), 10);
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 400);
    }, 5000);
}

function renderUI() {
    const radarBody = document.getElementById('radar-body');
    if (!radarBody) return;

    const displayList = allConnections.slice(0, 100);
    let vtActive = false;

    if (displayList.length === 0) {
        radarBody.innerHTML = '<tr><td colspan="11" style="text-align:center; padding: 5rem; color: var(--text-dim);"><div style="font-size:1.2rem; font-weight:800; letter-spacing:0.2em; margin-bottom:1rem;">[ SCANNING FOR ACTIVE FLOWS ]</div><div style="font-size:0.7rem;">Kharma Sentinel is waiting for network activity. No external threats detected in this cycle.</div></td></tr>';
        return;
    } else if (radarBody.innerHTML.includes("WAITING FOR NETWORK ACTIVITY") || radarBody.innerHTML.includes("SCANNING FOR ACTIVE FLOWS")) {
        radarBody.innerHTML = '';
    }

    // 1. Map Updates (Deferred to map module)
    if (typeof updateMapTelemetry === 'function') updateMapTelemetry();

    // 2. Table Updates
    const now = Date.now();
    const ROW_TTL = 5000; // 5 seconds persistence for closed connections
    const currentBatchKeys = new Set();

    // Process active connections
    displayList.forEach(conn => {
        const rowKey = `${conn.pid}-${conn.remote_ip}`;
        currentBatchKeys.add(rowKey);

        const isThreat = conn.is_malware || conn.ai_score > 7;
        const isShielded = conn.is_shielded;
        const isCommunity = conn.is_flagged;
        if (isThreat) vtActive = true;

        const rowClass = `${isThreat ? "threat-row" : "row-hover"} ${isShielded ? 'shield-active' : ''}`;

        if (!_rowCache.has(rowKey)) {
            const tr = document.createElement('tr');
            tr.id = `row-${conn.pid}-${conn.remote_ip.split('.').join('-')}`;
            for (let i = 0; i < 11; i++) tr.appendChild(document.createElement('td'));
            radarBody.appendChild(tr);
            _rowCache.set(rowKey, { tr: tr, lastSeen: now, data: conn });
        }

        const entry = _rowCache.get(rowKey);
        const tr = entry.tr;
        entry.lastSeen = now;
        entry.data = conn; // Update stored data
        entry.isDecaying = false;

        if (tr.className !== rowClass) tr.className = rowClass;
        tr.style.opacity = "1";

        const statusData = getStatusData(conn, isThreat, isCommunity, isShielded);
        renderRowCells(tr, conn, isThreat, isCommunity, isShielded, statusData);
    });

    // Handle decaying rows and removal
    _rowCache.forEach((entry, rowKey) => {
        const tr = entry.tr;
        const age = now - entry.lastSeen;

        if (age > ROW_TTL) {
            tr.remove();
            _rowCache.delete(rowKey);
        } else if (age > 100) { // If not in current batch (with a small buffer)
            entry.isDecaying = true;
            tr.style.opacity = "0.4";
            tr.style.filter = "grayscale(1)";

            // Update status to DISCONNECTED for decaying rows
            const mockConn = { ...entry.data, in_kbps: 0, out_kbps: 0 };
            const statusData = { label: "DISCONNECTED", class: "status-dim" };
            renderRowCells(tr, mockConn, false, false, false, statusData);
        }
    });
}

function renderRowCells(tr, conn, isThreat, isCommunity, isShielded, statusData) {
    const isSelected = window._selectedIps && window._selectedIps.has(conn.remote_ip);
    const anomaliesHtml = (conn.anomalies || []).map(a => `<div style="color: #f87171; font-size: 0.6rem; margin-top: 2px;">• ${a}</div>`).join('');

    const cells = [
        { content: `<input type="checkbox" class="custom-checkbox row-checkbox" ${isSelected ? 'checked' : ''} onchange="toggleSelectIP('${conn.remote_ip}', this)">`, style: `text-align:center;` },
        { content: conn.process_name, style: `font-weight: 700; color: ${isThreat ? 'var(--danger)' : 'var(--success)'}` },
        { content: conn.pid, style: `color: var(--text-dim); font-size: 0.75rem;` },
        { content: conn.remote_address, style: `font-family: monospace;` },
        { content: conn.in_kbps > 0 ? (conn.in_kbps.toFixed(1) + ' <span style="font-size:0.6rem">KB/s</span>') : '—', style: `text-align: right; color: #3b82f6; font-weight: 700;` },
        { content: conn.out_kbps > 0 ? (conn.out_kbps.toFixed(1) + ' <span style="font-size:0.6rem">KB/s</span>') : '—', style: `text-align: right; color: #10b981; font-weight: 700;` },
        { content: conn.location, style: `color: var(--text-dim); font-size: 0.75rem;` },
        {
            content: `
                <div style="display:flex; flex-direction:column; gap:4px; min-width: 120px;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span class="badge-ai badge-ai-${conn.ai_level.toLowerCase()}">${conn.ai_level}</span>
                        <span style="font-weight: 800; color: var(--text-main); font-size: 0.65rem;">${conn.ai_score}</span>
                    </div>
                    <div class="ai-meter-bg">
                        <div class="ai-meter-fill" style="width: ${conn.ai_score * 10}%; background: ${conn.ai_score > 7.5 ? '#ef4444' : (conn.ai_score > 4.5 ? '#f59e0b' : '#10b981')}"></div>
                    </div>
                    ${anomaliesHtml}
                </div>
            `, style: `font-size: 0.7rem;`
        },
        { content: conn.vt_total > 0 ? (conn.vt_malicious > 0 ? `<span style="color: var(--danger); font-weight: bold;" class="blink">${conn.vt_malicious}/${conn.vt_total}</span>` : `<span style="color: var(--accent);">${conn.vt_total} Checks</span>`) : '-', style: `text-align: center;` },
        { content: `<span class="status-badge ${statusData.class}">${statusData.label}</span>`, style: `` },
        {
            content: `
                <div class="forensics-hub" id="hub-${conn.pid}-${conn.remote_ip.split('.').join('-')}">
                    <div class="hub-actions">
                        <button class="kill-btn ${isCommunity ? 'report-btn-active' : ''}" onclick="reportIP('${conn.remote_ip}', ${isCommunity})" title="${isCommunity ? 'Cancel Flag' : 'Report IP'}">
                            <i data-lucide="flag" style="width: 14px; height: 14px; color: ${isCommunity ? '#fff' : '#fbbf24'};"></i>
                        </button>
                        <button class="kill-btn" style="color: #60a5fa; border-color: rgba(96, 165, 250, 0.4);" onclick="startHunt(${conn.pid}, '${conn.process_name}')" title="Forensic Hunt">
                            <i data-lucide="search" style="width: 14px; height: 14px;"></i>
                        </button>
                        <button class="kill-btn" style="color: #34d399; border-color: rgba(52, 211, 153, 0.4);" onclick="generateSnapshot(${conn.pid})" title="PDF Report">
                            <i data-lucide="file-text" style="width: 14px; height: 14px;"></i>
                        </button>
                    </div>
                    <button class="kill-btn hub-trigger" onclick="toggleHub('${conn.pid}-${conn.remote_ip.split('.').join('-')}')" title="Forensics Hub">
                        <i data-lucide="plus" style="width: 14px; height: 14px;"></i>
                    </button>
                    <button class="kill-btn ${isShielded ? 'shield-btn-active' : ''}" onclick="toggleShield('${conn.remote_ip}', ${isShielded})" title="${isShielded ? 'Cancel Block' : 'Shield IP'}">
                        <i data-lucide="shield${isShielded ? '-off' : ''}" style="width: 14px; height: 14px;"></i>
                    </button>
                    ${(conn.status === "stopped" || conn.status === "suspended") ? `
                        <button class="kill-btn" style="color: #34d399; border-color: #34d399;" onclick="resumePID(${conn.pid})" title="Resume Process">
                            <i data-lucide="play" style="width: 14px; height: 14px;"></i>
                        </button>
                    ` : `
                        <button class="kill-btn" style="color: #818cf8; border-color: #6366f1;" onclick="freezePID(${conn.pid})" title="Freeze Process">
                            <i data-lucide="snowflake" style="width: 14px; height: 14px;"></i>
                        </button>
                    `}
                    <button class="kill-btn" onclick="killPID(${conn.pid})" title="Kill Process">
                        <i data-lucide="zap" style="width: 14px; height: 14px;"></i>
                    </button>
                </div>
            `, style: `text-align: right; display: flex; gap: 8px; justify-content: flex-end;`
        }
    ];

    cells.forEach((c, idx) => {
        const cell = tr.children[idx];
        if (cell.getAttribute('data-prev-content') !== c.content) {
            cell.innerHTML = c.content;
            cell.setAttribute('data-prev-content', c.content);
            if (c.style) cell.setAttribute('style', c.style);
        }
    });
    const vtStatusElement = document.getElementById('vt-status');
    vtStatusElement.innerText = vtActive ? "LINKED" : "STANDBY";
    vtStatusElement.style.color = vtActive ? "var(--accent)" : "var(--text-dim)";

    const totalIn = allConnections.reduce((acc, c) => acc + (c.in_kbps || 0), 0);
    const totalOut = allConnections.reduce((acc, c) => acc + (c.out_kbps || 0), 0);
    document.getElementById('total-bw').innerText = `${(totalIn + totalOut).toFixed(2)} KB/s`;

    if (typeof updateChart === 'function') updateChart(totalIn, totalOut);

    if (window._lucideTimer) clearTimeout(window._lucideTimer);
    window._lucideTimer = setTimeout(() => {
        if (typeof lucide !== 'undefined') lucide.createIcons({ root: radarBody });
    }, 300);
}

function getStatusData(conn, isThreat, isCommunity, isShielded) {
    let label = isThreat ? "THREAT DETECTED" : conn.status;
    let className = isThreat ? "status-malware" : "";
    if (isCommunity && !isThreat) {
        label = `FLAGGED (${conn.community_reports || 0})`;
        className = "status-community";
    }
    if (isShielded) {
        label = "SHIELDED (BLOCKED) ";
        className = "status-community";
    }
    if (conn.status === "SENTINEL-KILLED") {
        label = "SENTINEL KILLED";
        className = "status-killed";
    }
    if (conn.status === "stopped" || conn.status === "suspended") {
        label = currentLang === 'AR' ? "قيد الحجر" : "QUARANTINED";
        className = "status-quarantined";
    }
    return { label, class: className };
}

function renderPackets(newPackets) {
    const container = document.getElementById('packet-stream');
    if (!container) return;
    let html = '';
    newPackets.slice(0, 10).forEach(pkt => {
        const protocolInfo = isPro ? `<span style="color:#fbbf24">[PRO]</span> ${pkt.proto}` : pkt.proto;
        html += `
            <div class="packet-line" style="border-left: 2px solid ${isPro ? '#fbbf24' : 'var(--accent)'}">
                <span class="packet-time" style="color:var(--text-dim);font-size:0.65rem;">${pkt.time}</span>
                <span class="packet-src-dst" style="color:#60a5fa;font-size:0.7rem;">${pkt.src} ➔ ${pkt.dst}</span>
                <span class="packet-proto" style="font-weight:bold;color:var(--accent);">${protocolInfo}</span>
                <span class="packet-info">${pkt.info}</span>
            </div>
        `;
    });
    container.insertAdjacentHTML('afterbegin', html);
    while (container.children.length > 50) container.removeChild(container.lastChild);
}

function toggleHub(hubId) {
    const hub = document.getElementById(`hub-${hubId}`);
    if (!hub) return;
    const isExpanded = hub.classList.contains('expanded');
    document.querySelectorAll('.forensics-hub').forEach(h => h.classList.remove('expanded'));
    if (!isExpanded) hub.classList.add('expanded');
    if (typeof lucide !== 'undefined') lucide.createIcons();
}

function toggleHistory() {
    const panel = document.getElementById('history-panel');
    if (!panel) return;
    panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
    if (panel.style.display === 'block') updateHistory();
}

var fullHistoryCache = [];
function scrubHistory(val) {
    const label = document.getElementById('scrub-label');
    if (val == 100) {
        if (label) label.innerText = "LIVE";
        renderHistoryTable(fullHistoryCache);
        return;
    }
    const index = Math.floor((val / 100) * (fullHistoryCache.length - 1));
    const filtered = fullHistoryCache.slice(0, index + 1);
    const targetTime = filtered.length > 0 ? filtered[filtered.length - 1].timestamp : "...";
    if (label) label.innerText = targetTime.split(' ')[1] || targetTime;
    renderHistoryTable(filtered);
}

function renderHistoryTable(events) {
    const tbody = document.getElementById('history-body');
    if (!tbody) return;
    if (!events || events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 2rem; color: var(--text-dim);">No events in this time range.</td></tr>';
        return;
    }
    const severityColors = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', info: '#6366f1' };
    const eventIcons = { THREAT: '🚨', BLOCKED: '🛡️', COMMUNITY_FLAG: '👥', DPI_ALERT: '⚠️' };
    let html = '';
    events.forEach(ev => {
        const color = severityColors[ev.severity] || '#6366f1';
        const icon = eventIcons[ev.event_type] || '•';
        html += `
            <tr style="border-bottom:1px solid rgba(255,255,255,0.04);">
                <td style="padding:0.6rem 1rem;color:var(--text-dim);font-size:0.7rem;">${ev.timestamp || '—'}</td>
                <td style="padding:0.6rem 1rem;"><span style="background:${color}22;color:${color};padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:700;">${icon} ${ev.event_type}</span></td>
                <td style="padding:0.6rem 1rem;font-family:monospace;color:${color};">${ev.ip || '—'}</td>
                <td style="padding:0.6rem 1rem;color:var(--text-main);">${ev.process || '—'}</td>
                <td style="padding:0.6rem 1rem;color:var(--text-dim);">${ev.location || '—'}</td>
                <td style="padding:0.6rem 1rem;color:var(--text-dim);font-size:0.75rem;">${ev.detail || '—'}</td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
}

async function updateHistory() {
    const statsEl = document.getElementById('history-stats');
    const filterEl = document.getElementById('history-filter');
    const filter = filterEl ? filterEl.value : '';
    const url = '/api/history' + (filter ? '?type=' + filter : '') + '?_=' + Date.now();
    try {
        const res = await fetch(url, { headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` } });
        const json = await res.json();
        if (json.status === 'success') {
            fullHistoryCache = json.data;
            const scrubber = document.getElementById('time-scrubber');
            if (scrubber) scrubber.value = 100;
            const label = document.getElementById('scrub-label');
            if (label) label.innerText = "LIVE";
            const eventIcons = { THREAT: '🚨', BLOCKED: '🛡️', COMMUNITY_FLAG: '👥', DPI_ALERT: '⚠️' };
            const stats = json.stats || {};
            const statsStr = Object.keys(stats).map(k => (eventIcons[k] || '•') + ' ' + k + ': ' + stats[k]).join(' | ');
            if (statsEl) statsEl.textContent = statsStr;
            renderHistoryTable(fullHistoryCache);
        }
    } catch (e) {
        console.error("History Load Error:", e);
    }
}

async function clearHistory() {
    if (!confirm("Clear all security event history? This cannot be undone.")) return;
    try {
        const res = await fetch('/api/history', { method: 'DELETE', headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` } });
        const data = await res.json();
        showToast("HISTORY CLEARED", data.message, "info");
        updateHistory();
    } catch (data) {
        showToast("CLEAR FAILED", "Failed to clear history.", "danger");
    }
}

async function addDemoEvents() {
    try {
        await fetch('/api/history/demo', { method: 'POST', headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` } });
        updateHistory();
    } catch (e) {
        console.error("Demo failed:", e);
    }
}

