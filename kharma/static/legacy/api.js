// KHARMA SENTINEL - API Communication Module

async function updateRadar() {
    try {
        const response = await fetch('/api/radar');
        if (!response.ok) throw new Error(`HTTP_${response.status}`);
        const json = await response.json();

        if (json.status === 'success') {
            const rawData = json.data;
            isPro = json.is_pro || false;

            if (window.telemetryWorker) {
                window.telemetryWorker.postMessage({
                    type: 'PROCESS_TELEMETRY',
                    data: rawData,
                    filter: ""
                });
                if (!window._telemetryReceived) {
                    allConnections = rawData;
                    renderUI();
                }
            } else {
                allConnections = rawData;
                renderUI();
            }
        }
    } catch (e) {
        console.error("API Communication Failure:", e);
        if (!window._apiErrCount) window._apiErrCount = 0;
        window._apiErrCount++;
        if (window._apiErrCount > 5) {
            const radarBody = document.getElementById('radar-body');
            if (radarBody) {
                radarBody.innerHTML = '<tr><td colspan="11" style="text-align:center; padding: 4rem; color: var(--danger);"><div class="blink" style="font-size:1.5rem; margin-bottom:1rem;">⚠️ SENSOR OFFLINE</div>Backend connection lost. Ensure Kharma Service is running with Administrative privileges.</td></tr>';
            }
        }
    }
}

async function reportIP(ip, currentlyFlagged) {
    const method = currentlyFlagged ? 'DELETE' : 'POST';
    try {
        const url = method === 'DELETE' ? `/api/report?ip=${ip}` : '/api/report';
        const options = {
            method: method,
            headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
        };
        if (method === 'POST') {
            options.headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify({ ip: ip, reason: "Manual UI Flag" });
        }

        const res = await fetch(url, options);
        const data = await res.json();
        if (res.status === 200) {
            showToast(currentlyFlagged ? "FLAG REMOVED" : "IP REPORTED", data.message, "info");
        } else {
            showToast("ACTION FAILED", data.message, "warning");
        }
        updateRadar();
    } catch (e) {
        showToast("ACTION FAILED", "Failed to update community flag.", "danger");
    }
}

async function killPID(pid) {
    try {
        const res = await fetch(`/api/kill/${pid}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
        });
        const data = await res.json();
        if (res.status === 200) {
            showToast("PROCESS TERMINATED", data.message, "info");
        } else {
            showToast("KILL FAILED", data.message, "warning");
        }
        updateRadar();
    } catch (e) {
        showToast("ERROR", "Failed to execute kill command.", "danger");
    }
}

async function freezePID(pid) {
    try {
        const res = await fetch(`/api/quarantine/${pid}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
        });
        const data = await res.json();
        if (res.status === 200) {
            showToast("PROCESS FROZEN", data.message, "info");
        } else {
            showToast("FREEZE FAILED", data.message, "warning");
        }
        updateRadar();
    } catch (e) {
        showToast("ACTION FAILED", "Failed to freeze process.", "danger");
    }
}

async function resumePID(pid) {
    try {
        const res = await fetch(`/api/resume/${pid}`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
        });
        const data = await res.json();
        if (res.status === 200) {
            showToast("PROCESS RESUMED", data.message, "info");
        } else {
            showToast("RESUME FAILED", data.message, "warning");
        }
        updateRadar();
    } catch (e) {
        showToast("ACTION FAILED", "Failed to resume process.", "danger");
    }
}

async function toggleShield(ip, currentlyBlocked) {
    const method = currentlyBlocked ? 'DELETE' : 'POST';
    try {
        const res = await fetch('/api/shield', {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${SESSION_TOKEN}`
            },
            body: JSON.stringify({ ip: ip })
        });
        const data = await res.json();
        if (res.status === 200) {
            showToast("SHIELD UPDATED", data.message, "info");
        } else {
            showToast("SHIELD FAILED", data.message, "danger");
        }
        updateRadar();
        if (typeof updateBlocklist === 'function') updateBlocklist();
    } catch (e) {
        showToast("SHIELD FAILED", "Operation failed. Ensure Kharma is running with Admin rights.", "danger");
    }
}

async function updatePackets() {
    try {
        const response = await fetch('/api/packets', {
            headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
        });
        const json = await response.json();
        if (json.status === 'success') {
            const newPackets = json.data;
            if (newPackets.length === 0) return;
            const latestHash = JSON.stringify(newPackets[0]);
            if (window._lastPacketHash === latestHash) return;
            window._lastPacketHash = latestHash;
            renderPackets(newPackets);
        }
    } catch (e) {
        console.error("DPI Stream Error:", e);
    }
}

async function updateHistory() {
    const filterEl = document.getElementById('history-filter');
    const filter = filterEl ? filterEl.value : '';
    const url = '/api/history' + (filter ? '?type=' + filter : '') + '?_=' + Date.now();

    try {
        const res = await fetch(url, {
            headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
        });
        const json = await res.json();
        if (json.status === 'success') {
            window.fullHistoryCache = json.data;
            document.getElementById('time-scrubber').value = 100;
            document.getElementById('scrub-label').innerText = "LIVE";

            const stats = json.stats || {};
            const statsStr = Object.keys(stats).map(k => (eventIcons[k] || '•') + ' ' + k + ': ' + stats[k]).join(' | ');
            const statsEl = document.getElementById('history-stats');
            const countEl = document.getElementById('history-count');
            if (statsEl) statsEl.textContent = statsStr;
            if (countEl) countEl.textContent = '📋 ' + window.fullHistoryCache.length + ' EVENTS';

            renderHistoryTable(window.fullHistoryCache);
        }
    } catch (e) {
        console.error("History Load Error:", e);
    }
}

async function fetchSettings() {
    try {
        const response = await fetch('/api/settings', {
            headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
        });
        return await response.json();
    } catch (e) {
        console.error("Settings load failed", e);
        return null;
    }
}

async function saveSettings(config) {
    try {
        const res = await fetch('/api/settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${SESSION_TOKEN}`
            },
            body: JSON.stringify(config)
        });
        return await res.json();
    } catch (e) {
        return { status: 'error', message: e.message };
    }
}
