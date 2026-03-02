// Kharma Sentinel - Lightweight App Logic

// Global State
let map;
let markerLayer;
let arcLayer;
let allConnections = [];
let _rowCache = new Map();
const ROW_TTL = 5000; // Keep closed connections on screen for 5s
let currentLang = 'EN';
let localCoords = { lat: 20, lon: 0 }; // Default global view

// Configuration
const CONFIG = {
    POLL_RATE: 1000,
    MAP_TILE: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
};

document.addEventListener("DOMContentLoaded", async () => {
    await initLocalCoords();
    initMap();
    initPolling();
    lucide.createIcons();
});

async function initLocalCoords() {
    try {
        const resp = await fetch('/api/status');
        const data = await resp.json();
        if (data.lat && data.lon) {
            localCoords = { lat: data.lat, lon: data.lon };
        }
    } catch (e) {
        console.error("Local Coords Error:", e);
    }
}

// --- MAP ENGINE ---
function initMap() {
    map = L.map('radar-map', {
        center: [localCoords.lat, localCoords.lon],
        zoom: 3,
        minZoom: 2,
        maxZoom: 18,
        zoomControl: false,
        attributionControl: false
    });

    L.tileLayer(CONFIG.MAP_TILE, {
        subdomains: 'abcd',
        maxZoom: 20
    }).addTo(map);

    markerLayer = L.featureGroup().addTo(map);
    arcLayer = L.featureGroup().addTo(map);

    // Custom Zoom
    L.control.zoom({ position: 'bottomright' }).addTo(map);
}

// Custom markers
const createMarkerIcon = (color) => L.divIcon({
    className: 'custom-div-icon',
    html: `<div style="background-color:${color}; width:10px; height:10px; border-radius:50%; box-shadow: 0 0 10px ${color}80;"></div>`,
    iconSize: [10, 10],
    iconAnchor: [5, 5]
});

function updateMap() {
    markerLayer.clearLayers();
    arcLayer.clearLayers();

    allConnections.forEach(conn => {
        if (!conn.lat || !conn.lon) return;

        const isThreat = conn.ai_score > 7 || conn.is_malware;
        const color = isThreat ? 'var(--danger)' : 'var(--success)';

        // Marker
        const marker = L.marker([conn.lat, conn.lon], {
            icon: createMarkerIcon(color)
        }).bindTooltip(`
            <div style="font-family:'JetBrains Mono'; font-size:12px;">
                <b style="color:${color}">${conn.process_name}</b><br>
                IP: ${conn.remote_ip}<br>
                Loc: ${conn.location}
            </div>
        `);
        markerLayer.addLayer(marker);

        // Dynamic local location from backend
        const myLat = localCoords.lat;
        const myLon = localCoords.lon;

        let path = [[myLat, myLon], [conn.lat, conn.lon]];
        // Shortest path logic for arcs crossing the pacific
        if (Math.abs(myLon - conn.lon) > 180) {
            let adjustedLon = conn.lon > myLon ? conn.lon - 360 : conn.lon + 360;
            path = [[myLat, myLon], [conn.lat, adjustedLon]];
        }

        const polyline = L.polyline(path, {
            color: color,
            weight: 1.5,
            opacity: 0.2,
            dashArray: '5, 10'
        });
        arcLayer.addLayer(polyline);
    });
}

// --- TABLE ENGINE ---
function renderTable() {
    const radarBody = document.getElementById('radar-body');
    const now = Date.now();
    const currentBatchKeys = new Set();

    // Process active connections
    allConnections.forEach(conn => {
        const rowKey = `${conn.pid}-${conn.remote_ip}`;
        currentBatchKeys.add(rowKey);

        const isThreat = conn.is_malware || conn.ai_score > 7;
        const rowClass = isThreat ? "threat-row" : "";

        if (!_rowCache.has(rowKey)) {
            const tr = document.createElement('tr');
            tr.id = `row-${conn.pid}-${conn.remote_ip}`;
            for (let i = 0; i < 9; i++) tr.appendChild(document.createElement('td'));
            radarBody.appendChild(tr);
            _rowCache.set(rowKey, { tr: tr, lastSeen: now, data: conn });
        }

        const entry = _rowCache.get(rowKey);
        const tr = entry.tr;
        entry.lastSeen = now;
        entry.data = conn;

        if (tr.className !== rowClass) tr.className = rowClass;
        tr.style.opacity = "1";
        tr.style.filter = "none";

        renderRowCells(tr, conn, isThreat, false);
    });

    // Handle decaying rows
    _rowCache.forEach((entry, rowKey) => {
        const { tr, lastSeen, data } = entry;
        const age = now - lastSeen;

        if (age > ROW_TTL) {
            tr.remove();
            _rowCache.delete(rowKey);
        } else if (!currentBatchKeys.has(rowKey)) {
            tr.style.opacity = "0.4";
            tr.style.filter = "grayscale(100%)";

            // Render as dead connection
            const mockConn = { ...data, in_kbps: 0, out_kbps: 0 };
            renderRowCells(tr, mockConn, false, true);
        }
    });
}

function renderRowCells(tr, conn, isThreat, isDead) {
    const aiColor = conn.ai_score > 7 ? 'var(--danger)' : (conn.ai_score > 4 ? 'var(--warning)' : 'var(--success)');
    const statusHtml = isDead ?
        `<span class="text-muted fw-light">CLOSED</span>` :
        `<span class="badge ${isThreat ? 'badge-threat' : 'badge-safe'}">${isThreat ? 'DETECTED' : 'ESTABLISHED'}</span>`;

    const cells = [
        { content: `<strong style="color: ${isThreat ? 'var(--danger)' : 'var(--text-main)'}">${conn.process_name}</strong>` },
        { content: `<span class="mono text-muted">${conn.pid}</span>` },
        { content: `<span class="mono">${conn.remote_address}</span>` },
        { content: `<span class="mono text-success">${conn.in_kbps > 0 ? conn.in_kbps.toFixed(1) : '0.0'}</span>`, className: "text-right" },
        { content: `<span class="mono text-danger">${conn.out_kbps > 0 ? conn.out_kbps.toFixed(1) : '0.0'}</span>`, className: "text-right" },
        { content: `<span class="text-muted">${conn.location}</span>` },
        { content: `<span style="color: ${aiColor}; font-weight: 600;">${conn.ai_level} <span class="mono text-muted">(${conn.ai_score})</span></span>` },
        { content: statusHtml, className: "text-right" },
        {
            content: `
            <div style="display:flex; gap:0.5rem; justify-content: flex-end;">
                <button class="action-btn" onclick="apiAction('report', '${conn.remote_ip}')" title="Flag IP"><i data-lucide="flag" style="width:14px; height:14px;"></i></button>
                <button class="action-btn danger" onclick="apiAction('kill', ${conn.pid})" title="Kill Process"><i data-lucide="zap" style="width:14px; height:14px;"></i></button>
            </div>
        `, className: "text-right"
        }
    ];

    cells.forEach((c, idx) => {
        const cell = tr.children[idx];
        if (c.className) cell.className = c.className;
        if (cell.innerHTML !== c.content) {
            cell.innerHTML = c.content;
        }
    });

    if (!tr.dataset.iconsRendered) {
        lucide.createIcons({ root: tr });
        tr.dataset.iconsRendered = "true";
    }
}

// --- DATA LAYER ---
function initPolling() {
    console.log('Telemetry polling initialized');

    async function fetchTelemetry() {
        try {
            const response = await fetch('/api/radar');
            if (!response.ok) return;
            const json = await response.json();

            if (json.status === 'success') {
                let processed = json.data;

                // 1. Tactical Sorting (Threats First -> AI Score -> PID)
                processed.sort((a, b) => {
                    if (a.is_malware !== b.is_malware) return a.is_malware ? -1 : 1;
                    if (a.ai_score !== b.ai_score) return b.ai_score - a.ai_score;
                    return b.pid - a.pid; // Stable fallback
                });

                allConnections = processed;

                // Render
                const countBadge = document.getElementById('conn-count');
                if (countBadge) countBadge.innerText = allConnections.length;

                renderTable();
                updateMap();
            }
        } catch (e) {
            console.error("Telemetry Endpoint Error:", e);
        }
    }

    fetchTelemetry();
    setInterval(fetchTelemetry, CONFIG.POLL_RATE);
}

// --- ACTION API ---
async function apiAction(endpoint, target) {
    const token = document.querySelector('meta[name="session-token"]').content;

    let url = `/api/${endpoint}`;
    let method = 'POST';
    let body = null;

    if (endpoint === 'kill') {
        url = `/api/kill/${target}`;
        method = 'DELETE';
    } else if (endpoint === 'report') {
        body = JSON.stringify({ ip: target, reason: "Manual UI Flag" });
    }

    const options = {
        method: method,
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        }
    };
    if (body) options.body = body;

    try {
        const response = await fetch(url, options);
        const data = await response.json();
        console.log(`Action ${endpoint} result:`, data);

        // Quick visual feedback by refreshing telemetry immediately
        if (response.status === 200) {
            // Success
        }
    } catch (e) {
        console.error(e);
    }
}

// --- SETTINGS LOGIC ---
function toggleSettings() {
    const panel = document.getElementById('settings-panel');
    const overlay = document.getElementById('overlay');
    panel.classList.toggle('active');
    overlay.classList.toggle('active');

    if (panel.classList.contains('active')) {
        loadSettings();
    }
}

function toggleField(id) {
    const input = document.getElementById(id);
    input.type = input.type === 'password' ? 'text' : 'password';
}

async function loadSettings() {
    const token = document.querySelector('meta[name="session-token"]').content;
    try {
        const response = await fetch('/api/settings', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        const json = await response.json();
        if (json.status === 'success') {
            document.getElementById('tg-token').value = json.data.telegram_bot_token || '';
            document.getElementById('tg-chat-id').value = json.data.telegram_chat_id || '';
        }
    } catch (e) {
        console.error("Load Settings Error:", e);
    }
}

async function saveSettings() {
    const token = document.querySelector('meta[name="session-token"]').content;
    const tgToken = document.getElementById('tg-token').value.trim();
    const tgChat = document.getElementById('tg-chat-id').value.trim();

    try {
        const response = await fetch('/api/settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                telegram_bot_token: tgToken,
                telegram_chat_id: tgChat
            })
        });
        const data = await response.json();
        alert(data.message || "Settings Saved");
    } catch (e) {
        console.error("Save Settings Error:", e);
        alert("Failed to save settings");
    }
}

async function testTelegram() {
    try {
        const response = await fetch('/api/settings/test', { method: 'POST' });
        const data = await response.json();
        alert(data.message || "Test Alert Sent");
    } catch (e) {
        console.error("Test Error:", e);
        alert("Failed to send test alert");
    }
}
