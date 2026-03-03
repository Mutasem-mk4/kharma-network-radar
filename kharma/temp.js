



        // Security: Prioritize JWT from localStorage for enterprise-grade sessions
        const SESSION_TOKEN = localStorage.getItem('kharma_jwt') || "{{ session_token }}";
        var radarBody = document.getElementById('radar-body');
        var connCountElement = document.getElementById('conn-count');
        var filterInput = document.getElementById('filter-input');
        var vtStatusElement = document.getElementById('vt-status');
        var packetStream = document.getElementById('packet-stream');

        var allConnections = [];
        var knownThreats = new Set();
        var lastPacketsJson = ""; // For diffing
        var isPro = false;
        var map;
        var bwChart;
        var chartData = {
            labels: [], datasets: [
                { label: 'Down', borderColor: '#3b82f6', backgroundColor: 'rgba(59, 130, 246, 0.1)', data: [], fill: true, tension: 0.4 },
                { label: 'Up', borderColor: '#10b981', backgroundColor: 'rgba(16, 185, 129, 0.1)', data: [], fill: true, tension: 0.4 }
            ]
        };
        var severityColors = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', info: '#6366f1' };
        var eventIcons = { THREAT: '🚨', BLOCKED: '🛡️', COMMUNITY_FLAG: '👥', DPI_ALERT: '⚠️' };

        // Sentinel 3D Assets
        var globe;
        var myLat = 31.9522;
        var myLon = 35.2332;

        try {
            if (typeof lucide !== 'undefined') {
                lucide.createIcons();
            } else {
                console.warn("Lucide icons failed to load.");
            }
        } catch (e) {
            console.error(e);
        }

        // Toast Notification System
        function showToast(title, message, type = 'danger') {
            const container = document.getElementById('toast-container');
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

            // Trigger entry animation
            setTimeout(() => toast.classList.add('show'), 10);

            // Remove after 5s Delay
            setTimeout(() => {
                toast.classList.remove('show');
                setTimeout(() => toast.remove(), 400);
            }, 5000);
        }

        // KHARMA SENTINEL - 2D Tactical Map Initialization (Leaflet)
        function initMap() {
            const mapEl = document.getElementById('radar-map');
            if (!mapEl) return;

            globe = L.map('radar-map', {
                zoomControl: false,
                attributionControl: false,
                worldCopyJump: true
            }).setView([myLat, myLon], 3);

            // Create a custom pane for labels so they stay above everything
            const labelPane = globe.createPane('labels');
            labelPane.style.zIndex = 650;
            labelPane.style.pointerEvents = 'none';

            // Base map: Voyager (No labels)
            L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager_nolabels/{z}/{x}/{y}{r}.png', {
                maxZoom: 19,
                attribution: '&copy; OpenStreetMap &copy; CARTO'
            }).addTo(globe);

            // High Contrast Label Layer on the labels pane
            L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager_only_labels/{z}/{x}/{y}{r}.png', {
                maxZoom: 19,
                pane: 'labels',
                opacity: 0.9
            }).addTo(globe);

            // Layer groups for persistent markers and arcs
            window._mapMarkers = L.layerGroup().addTo(globe);
            window._mapArcs = L.layerGroup().addTo(globe);
            window._markerCache = new Map(); // ip -> marker
            window._arcCache = new Map(); // ip -> arc

            // Add center marker (Sensor Hub)
            L.circleMarker([myLat, myLon], {
                radius: 7,
                fillColor: "var(--accent)",
                color: "#fff",
                weight: 2,
                opacity: 1,
                fillOpacity: 0.9
            }).addTo(globe).bindTooltip("<b style='color:var(--accent)'>LOCAL SENSOR HUB</b><br/>ACTIVE MONITORING", { permanent: false, direction: 'top' });

            console.log("Kharma Sentinel 2D Tactical Map Initialized with Landmarker Pane.");
        }

        // TELEMETRY WORKER INITIALIZATION (Phase 17)
        let telemetryWorker;
        try {
            telemetryWorker = new Worker('/static/telemetry-worker.js');
            telemetryWorker.onmessage = function (e) {
                if (e.data.type === 'TELEMETRY_READY') {
                    allConnections = e.data.data;
                    if (!window._renderRequested) {
                        window._renderRequested = true;
                        requestAnimationFrame(() => {
                            renderUI();
                            window._renderRequested = false;
                        });
                    }
                }
            };
        } catch (e) {
            console.warn("Web Worker failed to initialize. Falling back to main thread.");
        }

        // Fetch API
        async function updateRadar() {
            try {
                const response = await fetch('/api/radar');
                if (!response.ok) throw new Error(`HTTP_${response.status}`);
                const json = await response.json();
                if (json.status === 'success') {
                    const rawData = json.data;
                    isPro = json.is_pro || false;

                    if (telemetryWorker) {
                        telemetryWorker.postMessage({
                            type: 'PROCESS_TELEMETRY',
                            data: rawData,
                            filter: filterInput.value
                        });
                    } else {
                        // Fallback logic
                        allConnections = rawData;
                        renderUI();
                    }
                } else {
                    console.error("API Error:", json.message);
                }
            } catch (e) {
                console.error("API Communication Failure:", e);
                // If it fails repeatedly, show a hint
                if (!window._apiErrCount) window._apiErrCount = 0;
                window._apiErrCount++;
                if (window._apiErrCount > 5) {
                    radarBody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 2rem; color: var(--danger);">SENSOR OFFLINE (Backend connection lost). Retrying...</td></tr>';
                }
            }
        }

        // Initialize Row Cache for Differential Rendering
        const _rowCache = new Map(); // key: pid-ip

        function renderUI() {
            // Virtualization Lite: Render top 100 connections 
            const displayList = allConnections.slice(0, 100);

            let html = "";
            let vtActive = false;

            // 1. Optimized Map Telemetry (Tactical Clustering Phase 16)
            // - [x] Phase 16: Tactical Map & Landmark Visibility
            // - [x] Enhance place labels and contrast
            // - [x] Implement Tactical Clusters for city-level grouping
            // - [x] Add Tactical Info Box interaction
            if (globe) {
                const currentLocations = new Map(); // "lat,lon" -> [connections]

                allConnections.forEach(conn => {
                    if (conn.lat && conn.lon) {
                        const key = `${conn.lat.toFixed(2)},${conn.lon.toFixed(2)}`;
                        if (!currentLocations.has(key)) currentLocations.set(key, []);
                        currentLocations.get(key).push(conn);
                    }
                });

                const activeLocationKeys = new Set();

                currentLocations.forEach((conns, locKey) => {
                    activeLocationKeys.add(locKey);
                    const conn = conns[0]; // Representative
                    const count = conns.length;
                    const hasThreat = conns.some(c => c.is_malware || c.ai_score > 7);
                    const hasFlag = conns.some(c => c.is_community_flagged);
                    const hasShield = conns.some(c => c.is_shielded);

                    let color = hasThreat ? "var(--danger)" : "var(--accent)";
                    if (hasFlag && !hasThreat) color = "#f59e0b";
                    if (hasShield) color = "#6366f1";

                    // Update or Create Marker
                    if (window._markerCache.has(locKey)) {
                        const marker = window._markerCache.get(locKey);
                        marker.setLatLng([conn.lat, conn.lon]);
                        marker.setStyle({
                            fillColor: color,
                            radius: count > 1 ? 8 : 5,
                            className: hasThreat ? 'pulse-marker-2d' : ''
                        });

                        // Update Tactical Info Box
                        const infoHtml = `
                            <div style="padding: 4px; font-family: 'JetBrains Mono', monospace;">
                                <b style="color:${color}">${count > 1 ? `[CLUSTER] ${count} FLOWS` : conn.process_name}</b><br/>
                                <span style="font-size:0.65rem; color:var(--text-dim);">${conn.location}</span><br/>
                                ${conns.slice(0, 3).map(c => `<div style="font-size:0.6rem; border-top:1px solid rgba(255,255,255,0.1); margin-top:2px;">• ${c.remote_ip}</div>`).join('')}
                                ${count > 3 ? `<div style="font-size:0.6rem; color:var(--accent);">+ ${count - 3} more...</div>` : ''}
                            </div>
                        `;
                        marker.setTooltipContent(infoHtml);
                    } else {
                        const marker = L.circleMarker([conn.lat, conn.lon], {
                            radius: count > 1 ? 8 : 5,
                            fillColor: color,
                            color: "#fff",
                            weight: 1,
                            opacity: 1,
                            fillOpacity: 0.8,
                            className: hasThreat ? 'pulse-marker-2d' : ''
                        }).bindTooltip("");
                        window._mapMarkers.addLayer(marker);
                        window._markerCache.set(locKey, marker);
                    }

                    // Arcs: We still want individual arcs for clarity or just one arc per cluster? 
                    // Let's do one primary arc per cluster to reduce clutter as requested.
                    if (!window._arcCache.has(locKey)) {
                        const arc = L.polyline([[myLat, myLon], [conn.lat, conn.lon]], {
                            color: color,
                            weight: 1,
                            opacity: 0.3,
                            dashArray: '5, 5',
                            className: 'tactical-arc'
                        });
                        window._mapArcs.addLayer(arc);
                        window._arcCache.set(locKey, arc);
                    }
                });

                // Cleanup stale layers (markers)
                window._markerCache.forEach((marker, locKey) => {
                    if (!activeLocationKeys.has(locKey)) {
                        window._mapMarkers.removeLayer(marker);
                        window._markerCache.delete(locKey);
                    }
                });
                // Cleanup stale arcs
                window._arcCache.forEach((arc, locKey) => {
                    if (!activeLocationKeys.has(locKey)) {
                        window._mapArcs.removeLayer(arc);
                        window._arcCache.delete(locKey);
                    }
                });
            }

            // 2. Differential Table Row Management
            const currentPids = new Set();
            displayList.forEach(conn => {
                const rowKey = `${conn.pid}-${conn.remote_ip}`;
                currentPids.add(rowKey);

                const searchStr = `${conn.process_name} ${conn.remote_address} ${conn.location}`.toLowerCase();
                const isFiltered = filter && !searchStr.includes(filter);

                const isThreat = conn.is_malware || conn.ai_score > 7;
                const isShielded = conn.is_shielded;
                const isCommunity = conn.is_community_flagged;

                if (isThreat) vtActive = true;

                // 3. Real-time Security Toasts
                if (isThreat && !knownThreats.has(conn.remote_ip)) {
                    knownThreats.add(conn.remote_ip);
                    showToast("MALWARE DETECTED", `Process <b>${conn.process_name}</b> connecting to malicious IP: ${conn.remote_ip}`, "danger");
                }
                if (isShielded && !knownThreats.has(`shield-${conn.remote_ip}`)) {
                    knownThreats.add(`shield-${conn.remote_ip}`);
                    showToast("CONNECTION BLOCKED", `Firewall isolated target: ${conn.remote_ip}`, "info");
                }

                const rowClass = `${isThreat ? "threat-row" : "row-hover"} ${isShielded ? 'shield-active' : ''}`;

                if (!_rowCache.has(rowKey)) {
                    // Create New Row
                    const tr = document.createElement('tr');
                    tr.id = `row-${conn.pid}-${conn.remote_ip.split('.').join('-')}`;
                    // Initialize exactly 10 empty cells for stability
                    for (let i = 0; i < 10; i++) tr.appendChild(document.createElement('td'));
                    radarBody.appendChild(tr);
                    _rowCache.set(rowKey, tr);
                }

                const tr = _rowCache.get(rowKey);
                if (tr.className !== rowClass) tr.className = rowClass;
                if (tr.style.display !== '') tr.style.display = '';

                // Build Status Label
                let statusLabel = isThreat ? "THREAT DETECTED" : conn.status;
                let statusClass = isThreat ? "status-malware" : "";
                if (isCommunity && !isThreat) {
                    statusLabel = `FLAGGED (${conn.community_reports || 0})`;
                    statusClass = "status-community";
                }
                if (isShielded) {
                    statusLabel = "SHIELDED (BLOCKED)";
                    statusClass = "status-community";
                }
                if (conn.status === "SENTINEL-KILLED") {
                    statusLabel = "SENTINEL KILLED";
                    statusClass = "status-killed";
                }

                // AI Intel Content with Anomalies
                const anomaliesHtml = (conn.anomalies || []).map(a => `<div style="color: #f87171; font-size: 0.6rem; margin-top: 2px;">• ${a}</div>`).join('');

                const isSelected = window._selectedIps && window._selectedIps.has(conn.remote_ip);
                const cells = [
                    { content: `<input type="checkbox" class="custom-checkbox row-checkbox" ${isSelected ? 'checked' : ''} onchange="toggleSelectIP('${conn.remote_ip}', this)">`, style: `text-align:center;` },
                    { content: conn.process_name, style: `font-weight: 700; color: ${isThreat ? 'var(--danger)' : 'var(--accent)'}` },
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
                    { content: `<span class="status-badge ${statusClass}">${statusLabel}</span>`, style: `` },
                    {
                        content: `
                        <div class="forensics-hub" id="hub-${conn.pid}">
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
                            <button class="kill-btn hub-trigger" onclick="toggleHub(${conn.pid})" title="Forensics Hub">
                                <i data-lucide="plus" style="width: 14px; height: 14px;"></i>
                            </button>
                            <button class="kill-btn ${isShielded ? 'shield-btn-active' : ''}" onclick="toggleShield('${conn.remote_ip}', ${isShielded})" title="${isShielded ? 'Cancel Block' : 'Shield IP'}">
                                <i data-lucide="shield${isShielded ? '-off' : ''}" style="width: 14px; height: 14px;"></i>
                            </button>
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
            });

            // 3. Cleanup stale rows from cache and DOM
            const displayIds = new Set(displayList.map(c => `${c.pid}-${c.remote_ip}`));
            _rowCache.forEach((tr, id) => {
                if (!displayIds.has(id)) {
                    tr.remove();
                    _rowCache.delete(id);
                }
            });

            // 3. Update Totals & Stats (Lower frequency/Deferred)
            connCountElement.innerText = allConnections.length;
            vtStatusElement.innerText = vtActive ? "LINKED" : "STANDBY";
            vtStatusElement.style.color = vtActive ? "var(--accent)" : "var(--text-dim)";

            const totalIn = allConnections.reduce((acc, c) => acc + (c.in_kbps || 0), 0);
            const totalOut = allConnections.reduce((acc, c) => acc + (c.out_kbps || 0), 0);
            document.getElementById('total-bw').innerText = `${(totalIn + totalOut).toFixed(2)} KB/s`;

            updateChart(totalIn, totalOut);

            // Re-trigger Lucide only for new elements if needed, but throttle it
            if (window._lucideTimer) clearTimeout(window._lucideTimer);
            window._lucideTimer = setTimeout(() => {
                if (typeof lucide !== 'undefined') lucide.createIcons();
            }, 50);
        }

        let _lastChartTime = 0;
        function updateChart(tin, tout) {
            if (!bwChart) return;
            const nowMs = Date.now();
            if (nowMs - _lastChartTime < 1000) return; // Throttle to 1Hz
            _lastChartTime = nowMs;

            const timeStr = new Date().toLocaleTimeString();
            chartData.labels.push(timeStr);
            chartData.datasets[0].data.push(tin);
            chartData.datasets[1].data.push(tout);

            if (chartData.labels.length > 20) {
                chartData.labels.shift();
                chartData.datasets[0].data.shift();
                chartData.datasets[1].data.shift();
            }
            bwChart.update('none');
        }

        function initChart() {
            const ctx = document.getElementById('bw-chart').getContext('2d');
            bwChart = new Chart(ctx, {
                type: 'line',
                data: chartData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { display: false },
                        y: {
                            beginAtZero: true,
                            grid: { color: 'rgba(255,255,255,0.05)' },
                            ticks: { color: 'rgba(255,255,255,0.5)', font: { size: 10 } }
                        }
                    }
                }
            });
        }

        async function reportIP(ip, currentlyFlagged) {
            const method = currentlyFlagged ? 'DELETE' : 'POST';
            const action = currentlyFlagged ? 'CANCEL FLAG' : 'FLAG AS MALICIOUS';
            if (!confirm(`CONFIRM COMMUNITY ACTION:\nDo you want to ${action} for IP ${ip}?`)) return;

            try {
                const url = method === 'DELETE' ? `/api/report?ip=${ip}` : '/api/report';
                const options = {
                    method: method,
                    headers: {
                        'Authorization': `Bearer ${SESSION_TOKEN}`
                    }
                };
                if (method === 'POST') {
                    options.headers['Content-Type'] = 'application/json';
                    options.body = JSON.stringify({ ip: ip, reason: "Manual UI Flag" });
                }

                const res = await fetch(url, options);
                const data = await res.json();
                showToast(currentlyFlagged ? "FLAG REMOVED" : "IP REPORTED", data.message, "info");
                updateRadar();
            } catch (e) {
                showToast("ACTION FAILED", "Failed to update community flag.", "danger");
            }
        }

        async function killPID(pid) {
            if (!confirm("COMMAND CONFIRMATION: Terminate and isolate process " + pid + "?")) return;
            const res = await fetch(`/api/kill/${pid}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
            });
            const data = await res.json();
            alert(data.message);
            updateRadar();
        }

        function toggleHub(pid) {
            const hub = document.getElementById(`hub-${pid}`);
            const isExpanded = hub.classList.contains('expanded');

            // Close others
            document.querySelectorAll('.forensics-hub').forEach(h => h.classList.remove('expanded'));

            if (!isExpanded) {
                hub.classList.add('expanded');
            }
            if (typeof lucide !== 'undefined') lucide.createIcons();
        }

        // BULK ACTION LOGIC (Phase 15)
        window._selectedIps = new Set();
        function toggleSelectIP(ip, el) {
            if (el.checked) window._selectedIps.add(ip);
            else window._selectedIps.delete(ip);
            updateBulkVisibility();
        }

        function toggleSelectAll(el) {
            const checkboxes = document.querySelectorAll('.row-checkbox');
            checkboxes.forEach(cb => {
                cb.checked = el.checked;
                const ip = cb.getAttribute('onchange').match(/'([^']+)'/)[1];
                if (el.checked) window._selectedIps.add(ip);
                else window._selectedIps.delete(ip);
            });
            updateBulkVisibility();
        }

        function updateBulkVisibility() {
            const bar = document.getElementById('bulk-bar');
            const countEl = document.getElementById('bulk-count');
            const count = window._selectedIps.size;

            if (count > 0) {
                countEl.innerText = `${count} IPs SELECTED`;
                bar.classList.add('active');
            } else {
                bar.classList.remove('active');
            }
        }

        function clearSelection() {
            window._selectedIps.clear();
            document.querySelectorAll('.custom-checkbox').forEach(cb => cb.checked = false);
            updateBulkVisibility();
            renderUI();
        }

        async function bulkAction(type) {
            const ips = Array.from(window._selectedIps);
            if (ips.length === 0) return;

            const action = type === 'shield' ? 'Shield (Block)' : 'Report (Flag)';
            if (!confirm(`BULK EXECUTION:\nPerform ${action} on ${ips.length} IPs?`)) return;

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
            clearSelection();
            updateRadar();
            if (type === 'shield') updateBlocklist();
        }


        function toggleHistory() {
            const panel = document.getElementById('history-panel');
            panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
            if (panel.style.display === 'block') updateHistory();
        }

        var fullHistoryCache = [];
        function scrubHistory(val) {
            const label = document.getElementById('scrub-label');
            const tbody = document.getElementById('history-body');

            if (val == 100) {
                label.innerText = "LIVE";
                renderHistoryTable(fullHistoryCache);
                return;
            }

            const index = Math.floor((val / 100) * (fullHistoryCache.length - 1));
            const filtered = fullHistoryCache.slice(0, index + 1);
            const targetTime = filtered.length > 0 ? filtered[filtered.length - 1].timestamp : "...";
            label.innerText = targetTime.split(' ')[1] || targetTime;

            renderHistoryTable(filtered);
        }

        function renderHistoryTable(events) {
            const tbody = document.getElementById('history-body');
            if (!events || events.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 2rem; color: var(--text-dim);">No events in this time range.</td></tr>';
                return;
            }

            let html = '';
            events.forEach(ev => {
                const color = severityColors[ev.severity] || '#6366f1';
                const icon = eventIcons[ev.event_type] || '•';
                html += `
                    <tr style="border-bottom:1px solid rgba(255,255,255,0.04);">
                        <td class="checkbox-cell">
                            <input type="checkbox" class="custom-checkbox" data-ip="${ev.ip}" onchange="updateBulkBar()">
                        </td>
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
            var statsEl = document.getElementById('history-stats');
            var countEl = document.getElementById('history-count');

            var filterEl = document.getElementById('history-filter');
            var filter = filterEl ? filterEl.value : '';
            var url = '/api/history' + (filter ? '?type=' + filter : '') + '?_=' + Date.now();

            try {
                var res = await fetch(url, {
                    headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
                });
                var json = await res.json();
                if (json.status === 'success') {
                    fullHistoryCache = json.data;
                    document.getElementById('time-scrubber').value = 100;
                    document.getElementById('scrub-label').innerText = "LIVE";

                    var stats = json.stats || {};
                    var statsStr = Object.keys(stats).map(function (k) { return (eventIcons[k] || '•') + ' ' + k + ': ' + stats[k]; }).join(' | ');
                    if (statsEl) statsEl.textContent = statsStr;
                    if (countEl) countEl.textContent = '📋 ' + fullHistoryCache.length + ' EVENTS';

                    renderHistoryTable(fullHistoryCache);
                }
            } catch (e) {
                console.error("History Load Error:", e);
            }
        }

        async function clearHistory() {
            if (!confirm("Clear all security event history? This cannot be undone.")) return;
            const res = await fetch('/api/history', {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
            });
            const data = await res.json();
            alert(data.message);
            updateHistory();
        }

        async function toggleGuardian() {
            const panel = document.getElementById('guardian-panel');
            if (panel.style.display === 'none') {
                panel.style.display = 'block';
                // Load existing settings
                const res = await fetch('/api/settings', {
                    headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
                });
                const json = await res.json();
                if (json.status === 'success') {
                    document.getElementById('tg-token').value = json.data.telegram_bot_token || '';
                    document.getElementById('tg-chat-id').value = json.data.telegram_chat_id || '';
                    document.getElementById('discord-webhook').value = json.data.discord_webhook_url || '';
                    document.getElementById('blocked-countries').value = (json.data.blocked_countries || []).join(', ');
                    document.getElementById('alert-threat').checked = json.data.alert_on_threat !== false;
                    document.getElementById('alert-block').checked = json.data.alert_on_block !== false;
                    document.getElementById('alert-dpi').checked = json.data.alert_on_dpi !== false;
                }
            } else {
                panel.style.display = 'none';
            }
        }

        async function saveGuardianSettings() {
            const config = {
                telegram_bot_token: document.getElementById('tg-token').value,
                telegram_chat_id: document.getElementById('tg-chat-id').value,
                discord_webhook_url: document.getElementById('discord-webhook').value,
                blocked_countries: document.getElementById('blocked-countries').value.split(',').map(s => s.trim().toUpperCase()).filter(s => s),
                alert_on_threat: document.getElementById('alert-threat').checked,
                alert_on_block: document.getElementById('alert-block').checked,
                alert_on_dpi: document.getElementById('alert-dpi').checked,
            };
            const res = await fetch('/api/settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${SESSION_TOKEN}`
                },
                body: JSON.stringify(config)
            });
            const data = await res.json();
            alert(data.message);
        }

        async function sendTestAlert() {
            try {
                const res = await fetch('/api/settings/test', {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
                });
                const data = await res.json();
                alert(data.message);
            } catch (e) {
                alert("Test failed. Is the server running?");
            }
        }

        async function addDemoEvents() {
            await fetch('/api/history/demo', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
            });
            await updateHistory();
        }

        async function toggleShield(ip, currentlyBlocked) {
            const method = currentlyBlocked ? 'DELETE' : 'POST';
            const action = currentlyBlocked ? 'UNBLOCK' : 'BLOCK';
            if (!confirm(`CONFIRM FIREWALL ${action}:\nTargets: ${ip}\nReason: Malicious Activity Detected.`)) return;

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
                alert(data.message);
                updateRadar();
                updateBlocklist();
            } catch (e) {
                alert("Shield operation failed. Ensure you have Admin rights.");
            }
        }

        async function updateBlocklist() {
            try {
                const res = await fetch('/api/shield', {
                    headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
                });
                const json = await res.json();
                if (json.status === 'success') {
                    const container = document.getElementById('blocklist-content');
                    if (json.data.length === 0) {
                        container.innerHTML = "No IPs represent a block condition.";
                        return;
                    }
                    let html = '<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 10px;">';
                    json.data.forEach(ip => {
                        html += `
                 <div style="background: rgba(99, 102, 241, 0.1); border: 1px solid rgba(99, 102, 241, 0.3); padding: 5px 10px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center;">
                                <span>${ip}</span>
                                <button onclick="toggleShield('${ip}', true)" style="background: none; border: none; color: var(--danger); cursor: pointer;">×</button>
                            </div>
                        `;
                    });
                    html += '</div>';
                    container.innerHTML = html;
                }
            } catch (e) { }
        }

        function toggleLicense() {
            const panel = document.getElementById('license-panel');
            panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
        }

        async function activatePro() {
            const key = document.getElementById('license-key').value;
            try {
                const res = await fetch('/api/license', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${SESSION_TOKEN}`
                    },
                    body: JSON.stringify({ key: key })
                });
                const data = await res.json();
                if (data.status === 'success') {
                    isPro = true;
                    applyProUI();
                    showToast("PRO ACTIVATED", "Enterprise features are now online.", "info");
                    toggleLicense();
                } else {
                    alert("Activation Failed: " + data.message);
                }
            } catch (e) { alert("Error: " + e.message); }
        }

        // --- LOCALIZATION ENGINE (Phase 7.4) ---
        let currentLang = 'EN';
        const translations = {
            'EN': {
                'brand_tier': '_SENTINEL',
                'sys_status': 'System Status',
                'active_sockets': 'Active Sockets',
                'vt_engine': 'VT Engine',
                'comm_score': 'Community Score',
                'auto_shield': 'Automated Shield',
                'throughput': 'Throughput',
                'hive_scale': 'Hive Scale',
                'guardian': 'Guardian Bot',
                'history': 'History',
                'license': 'License Tier',
                'radar_title': 'LIVE PROCESS RADAR',
                'search_placeholder': 'Search processes, IPs, or locations...',
                'th_process': 'Process',
                'th_pid': 'PID',
                'th_target': 'Remote Target',
                'th_ai': 'AI Intel',
                'th_vt': 'VT Scan',
                'th_status': 'Security Status',
                'th_action': 'Action',
                'wr_feed': 'Tactical Feed',
                'wr_threat': 'Threat Level',
                'wr_exit': 'Exit War Room',
                'wr_active': 'WAR ROOM ACTIVE'
            },
            'AR': {
                'brand_tier': '_الحارس',
                'sys_status': 'حالة النظام',
                'active_sockets': 'المنافذ النشطة',
                'vt_engine': 'محرك VT',
                'comm_score': 'سمعة المجتمع',
                'auto_shield': 'الدرع التلقائي',
                'throughput': 'معدل النقل',
                'hive_scale': 'نطاق الخلية',
                'guardian': 'بوت الحارس',
                'history': 'السجل',
                'license': 'فئة الترخيص',
                'radar_title': 'رادار العمليات المباشر',
                'search_placeholder': 'ابحث عن العمليات، العناوين، أو المواقع...',
                'th_process': 'العملية',
                'th_pid': 'المعرف',
                'th_target': 'الهدف البعيد',
                'th_ai': 'ذكاء اصطناعي',
                'th_vt': 'فحص VT',
                'th_status': 'الحالة الأمنية',
                'th_info': 'التفاصيل',
                'wr_feed': 'التغذية التكتيكية',
                'wr_threat': 'مستوى التهديد',
                'wr_exit': 'خروج من وضع العمليات',
                'wr_active': 'وضع العمليات نشط'
            }
        };

        translations['EN']['wr_active'] = 'WAR ROOM ACTIVE';
        translations['AR']['wr_active'] = 'وضع العمليات نشط';
        translations['EN']['wr_exit'] = 'Exit War Room';
        translations['AR']['wr_exit'] = 'خروج من وضع العمليات';
        translations['EN']['wr_feed'] = 'Tactical Feed';
        translations['AR']['wr_feed'] = 'التغذية التكتيكية';
        translations['EN']['wr_threat'] = 'Threat Level';
        translations['AR']['wr_threat'] = 'مستوى التهديد';

        translations['EN']['wiz_title_1'] = 'WELCOME TO SENTINEL';
        translations['AR']['wiz_title_1'] = 'مرحباً بك في الحارس (SENTINEL)';
        translations['EN']['wiz_text_1'] = 'Your tactical firewall is online. Kharma Sentinel is now watching over your network processes in real-time.';
        translations['AR']['wiz_text_1'] = 'جدار الحماية التكتيكي الخاص بك متصل. "كارما الحارس" يراقب الآن عمليات شبكتك في الوقت الفعلي.';
        translations['EN']['wiz_title_2'] = 'GUARDIAN BOT';
        translations['AR']['wiz_title_2'] = 'بوت الحارس';
        translations['EN']['wiz_text_2'] = 'Stay alerted! Configure Telegram or Discord webhooks to receive high-priority threat notifications on your mobile devices.';
        translations['AR']['wiz_text_2'] = 'ابقَ على اطلاع! قم بإعداد تنبيهات تيليجرام أو ديسكورد لتلقي إشعارات التهديدات عالية الأولوية على أجهزة المحمول.';
        translations['EN']['wiz_title_3'] = 'ENTERPRISE PRO';
        translations['AR']['wiz_title_3'] = 'إصدار ENTERPRISE PRO';
        translations['EN']['wiz_text_3'] = 'Unlock autonomous defense, DPI+ protocol analysis, and multi-node swarm management with a Pro license.';
        translations['AR']['wiz_text_3'] = 'افتح ميزات الدفاع التلقائي، وتحليل البروتوكولات المتقدم (DPI+)، وإدارة العقد المتعددة باستخدام ترخيص Pro.';
        translations['EN']['wiz_launch'] = 'Launch Dashboard';
        translations['AR']['wiz_launch'] = 'بدء لوحة التحكم';
        translations['EN']['wiz_next'] = 'Next';
        translations['AR']['wiz_next'] = 'التالي';
        translations['EN']['wiz_back'] = 'Back';
        translations['AR']['wiz_back'] = 'السابق';

        function applyProUI() {
            isPro = true;
            document.getElementById('license-label').innerText = (currentLang === 'AR' ? 'محترف' : 'PRO');
            document.getElementById('license-label').style.color = "#fbbf24";
            document.getElementById('system-ver-label').innerText = (currentLang === 'AR' ? 'إصدار V11.0.1-PRO حماية المؤسسات' : "V11.0.1-PRO ENTERPRISE DEFENSE");

            applyTranslations();

            // Unlock Pro panels
            document.getElementById('swarm-panel').style.opacity = "1";
            document.getElementById('swarm-overlay').style.display = "none";
        }

        function toggleLanguage() {
            currentLang = (currentLang === 'EN' ? 'AR' : 'EN');
            document.getElementById('current-lang').innerText = currentLang;

            if (currentLang === 'AR') {
                document.body.classList.add('rtl');
            } else {
                document.body.classList.remove('rtl');
            }

            applyTranslations();
            if (isPro) applyProUI();

            // Persist setting
            fetch('/api/settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${SESSION_TOKEN}`
                },
                body: JSON.stringify({ 'language': currentLang })
            });
        }

        function applyTranslations() {
            const t = translations[currentLang];

            // Update labels with specific IDs or structural selection
            document.querySelectorAll('.stat-label').forEach(el => {
                const text = el.innerText.trim();
                if (text === 'System Status' || text === 'حالة النظام') el.innerText = t.sys_status;
                if (text === 'Active Sockets' || text === 'المنافذ النشطة') el.innerText = t.active_sockets;
                if (text === 'VT Engine' || text === 'محرك VT') el.innerText = t.vt_engine;
                if (text === 'Community Score' || text === 'سمعة المجتمع') el.innerText = t.comm_score;
                if (text === 'Automated Shield' || text === 'الدرع التلقائي') el.innerText = t.auto_shield;
                if (text === 'Throughput' || text === 'معدل النقل') el.innerText = t.throughput;
                if (text === 'Hive Scale' || text === 'نطاق الخلية') el.innerText = t.hive_scale;
                if (text === 'Guardian Bot' || text === 'بوت الحارس') el.innerText = t.guardian;
                if (text === 'History' || text === 'السجل') el.innerText = t.history;
                if (text === 'License Tier' || text === 'فئة الترخيص') el.innerText = t.license;
            });

            document.getElementById('brand-tier').innerText = (isPro ? (currentLang === 'AR' ? '_محترف' : '_PRO') : t.brand_tier);
            document.querySelector('.panel-title').childNodes[2].textContent = ' ' + t.radar_title;
            document.getElementById('filter-input').placeholder = t.search_placeholder;

            // Table Headers
            const headers = document.querySelectorAll('thead th');
            if (headers.length >= 10) {
                headers[0].innerText = t.th_process;
                headers[1].innerText = t.th_pid;
                headers[2].innerText = t.th_target;
                headers[6].childNodes[0].textContent = t.th_ai + ' ';
                headers[7].innerText = t.th_vt;
                headers[8].innerText = t.th_status;
                headers[9].innerText = t.th_action;
            }

            // War Room Labels (Phase 8)
            const wrFeed = document.getElementById('wr-feed-label');
            const wrActive = document.getElementById('wr-active-label');
            const wrThreat = document.getElementById('wr-threat-label');
            const wrExit = document.getElementById('wr-exit-btn');
            if (wrExit) wrExit.innerText = t.wr_exit;

            // Wizard Labels (Phase 8)
            for (let i = 1; i <= 3; i++) {
                const title = document.getElementById(`wiz-title-${i}`);
                const text = document.getElementById(`wiz-text-${i}`);
                if (title) title.innerText = t[`wiz_title_${i}`];
                if (text) text.innerText = t[`wiz_text_${i}`];
            }
            const launchBtn = document.getElementById('finish-wiz-btn');
            if (launchBtn) launchBtn.innerText = t.wiz_launch;

            // Translate Wizard Buttons
            document.querySelectorAll('.wizard-footer button:not(.wr-exit-btn):not(#finish-wiz-btn)').forEach(btn => btn.innerText = t.wiz_next);
            document.querySelectorAll('.wizard-footer button.wr-exit-btn').forEach(btn => btn.innerText = t.wiz_back);
        }

        function toggleBlocklist() {
            const panel = document.getElementById('shield-panel');
            panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
            if (panel.style.display === 'block') updateBlocklist();
        }

        // DPI Logic: Poll every 1 second
        // Efficient Packet Streaming (Append-only + Throttled)
        async function updatePackets() {
            try {
                const response = await fetch('/api/packets', {
                    headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
                });
                const json = await response.json();

                if (json.status === 'success') {
                    const newPackets = json.data;
                    if (newPackets.length === 0) return;

                    // Simple hash check for changes
                    const latestHash = JSON.stringify(newPackets[0]);
                    if (window._lastPacketHash === latestHash) return;
                    window._lastPacketHash = latestHash;

                    const container = document.getElementById('packet-stream');
                    let html = '';
                    newPackets.slice(0, 10).forEach(pkt => { // Process small batch
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

                    // Prepend new packets and truncate
                    container.insertAdjacentHTML('afterbegin', html);
                    while (container.children.length > 50) {
                        container.removeChild(container.lastChild);
                    }
                }
            } catch (e) {
                console.error("DPI Stream Error:", e);
            }
        }

        async function startHunt(pid, name) {
            document.getElementById('hunt-pid-title').innerText = `${name} (PID: ${pid})`;
            document.getElementById('modal-overlay').style.display = 'block';
            document.getElementById('hunt-modal').style.display = 'flex';

            // Clear content
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

                    // Metadata
                    document.getElementById('hunt-meta').innerHTML = `
                        <b>Path:</b> ${d.exe || 'N/A'}<br>
                        <b>Command:</b> <span style="font-family:monospace; color: #60a5fa;">${(d.cmdline || []).join(' ')}</span><br>
                        <b>Created:</b> ${new Date(d.create_time * 1000).toLocaleString()}<br>
                        <b>Status:</b> ${d.status} | <b>Threads:</b> ${d.num_threads}
                    `;

                    // Heuristics
                    if (d.heuristics.length === 0) {
                        document.getElementById('hunt-heuristics').innerHTML = '<div style="color: var(--accent); font-size: 0.8rem;">No suspicious patterns found.</div>';
                    } else {
                        document.getElementById('hunt-heuristics').innerHTML = d.heuristics.map(h => `<div class="heuristic-tag">${h}</div>`).join('');
                    }

                    // Strings
                    document.getElementById('hunt-strings').innerHTML = (d.strings || []).map(s => `<div class="string-row">${s}</div>`).join('') || "No strings found.";

                    // Files
                    document.getElementById('hunt-files').innerHTML = (d.open_files || []).join('<br>') || "Access Denied.";

                    if (typeof lucide !== 'undefined') lucide.createIcons();
                } else {
                    document.getElementById('hunt-meta').innerHTML = `<span style="color:var(--danger)">Error: ${json.message}</span>`;
                }
            } catch (e) {
                alert("Forensic scan failed.");
            }
        }

        function closeHunt() {
            document.getElementById('modal-overlay').style.display = 'none';
            document.getElementById('hunt-modal').style.display = 'none';
        }

        async function generateSnapshot(pid) {
            const conn = allConnections.find(c => c.pid === pid);
            if (!conn) return;

            // Fetch Hunt Data
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
                            <b>Name:</b> ${conn.process_name}<br>
                            <b>PID:</b> ${conn.pid}<br>
                            <b>AI Anomaly Score:</b> ${conn.ai_score} / 10.0<br>
                            <b>Behavioral Label:</b> ${conn.ai_level}<br>
                            <b>Execution Path:</b> ${huntData.exe || 'N/A'}<br>
                            <b>Command Line:</b> ${(huntData.cmdline || []).join(' ') || 'N/A'}<br>
                            <b>User Context:</b> ${huntData.username || 'System/Admin'}
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
                        Digital Signature: ${isPro ? 'SENTINEL-SIG-' + Math.random().toString(36).substring(2, 10).toUpperCase() : 'N/A (Upgrade to Pro for Signing)'}
                    </div>

                    <script>
                        window.onload = () => { setTimeout(() => window.print(), 500); };
                    <\/script>
                </body>
                </html>
            `;

            const win = window.open('', '_blank');
            win.document.write(reportHtml);
            win.document.close();
        }

        async function updateSwarm() {
            if (!isPro) return; // Gate Enterprise Hub
            try {
                const response = await fetch('/api/swarm', {
                    headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
                });
                const json = await response.json();
                if (json.status === 'success') {
                    renderSwarm(json.data);
                }
            } catch (e) { }
        }

        function renderSwarm(data) {
            document.getElementById('hive-nodes').innerText = `${data.total_nodes + 1} NODES`;
            const list = document.getElementById('swarm-nodes-list');
            if (!list) return;
            if (data.nodes.length === 0) {
                list.innerHTML = '<div style="color: var(--text-dim); font-size: 0.8rem; grid-column: 1/-1;">No remote nodes connected. Join a node to expand your hive.</div>';
                return;
            }
            list.innerHTML = data.nodes.map(node => `
                <div class="forensic-card" style="border-left: 4px solid ${node.status === 'Online' ? '#10b981' : '#ef4444'}">
                    <div style="display:flex; justify-content:space-between; align-items:start;">
                        <div>
                            <div style="font-weight:700; font-size:0.9rem;">${node.name}</div>
                            <div style="font-size:0.7rem; color:var(--text-dim);">${node.url}</div>
                        </div>
                        <span class="status-badge ${node.status === 'Online' ? 'status-threat' : 'status-safe'}" style="background:${node.status === 'Online' ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)'}; color:${node.status === 'Online' ? '#10b981' : '#ef4444'}">${node.status}</span>
                    </div>
                    <div style="margin-top:10px; display:flex; gap:15px; font-size:0.75rem;">
                        <span style="color:#60a5fa"><b>${node.connections}</b> Flows</span>
                        <span style="color:#ef4444"><b>${node.threats}</b> Threats</span>
                    </div>
                    <button onclick="removeNode('${node.url}')" style="background:transparent; border:none; color:var(--text-dim); font-size:0.6rem; cursor:pointer; margin-top:10px; padding:0;">[ DISCONNECT ]</button>
                </div>
            `).join('');
            if (typeof lucide !== 'undefined') lucide.createIcons();
        }

        function openJoinNode() { document.getElementById('join-node-modal').style.display = 'block'; }
        function closeJoinNode() { document.getElementById('join-node-modal').style.display = 'none'; }

        async function submitJoinNode() {
            const url = document.getElementById('node-url').value;
            const token = document.getElementById('node-token').value;
            if (!url || !token) return alert("URL and Token required.");

            try {
                await fetch('/api/swarm', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${SESSION_TOKEN}`
                    },
                    body: JSON.stringify({ url, token })
                });
                closeJoinNode();
                updateSwarm();
            } catch (e) { alert("Failed to join hive."); }
        }

        async function removeNode(url) {
            if (!confirm("Disconnect node?")) return;
            await fetch(`/api/swarm?url=${encodeURIComponent(url)}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
            });
            updateSwarm();
        }

        function toggleWarRoom() {
            document.body.classList.toggle('war-room-active');
            if (document.body.classList.contains('war-room-active')) {
                showToast("WAR ROOM ACTIVE", "Switching to tactical SOC view.", "info");
            }
            // Trigger globe resize if needed
            if (typeof initMap === 'function') {
                setTimeout(initMap, 200);
            }
        }

        function simulateTraffic() {
            allConnections = [
                {
                    process_name: "Kharma_Beacon",
                    pid: 7777,
                    remote_address: "1.1.1.1:443",
                    remote_ip: "1.1.1.1",
                    location: "Cloudflare, US",
                    country_code: "US",
                    lat: 37.7749,
                    lon: -122.4194,
                    status: "ESTABLISHED",
                    in_kbps: 12.5,
                    out_kbps: 5.2,
                    ai_score: 1.2,
                    ai_level: "SAFE",
                    is_malware: false,
                    is_shielded: false,
                    vt_total: 70,
                    vt_malicious: 0,
                    anomalies: []
                },
                {
                    process_name: "Suspicious_Actor",
                    pid: 666,
                    remote_address: "45.122.1.5:8080",
                    remote_ip: "45.122.1.5",
                    location: "Unknown, RU",
                    country_code: "RU",
                    lat: 55.7558,
                    lon: 37.6173,
                    status: "ESTABLISHED",
                    in_kbps: 0.1,
                    out_kbps: 156.0,
                    ai_score: 8.9,
                    ai_level: "CRITICAL",
                    is_malware: true,
                    is_shielded: false,
                    vt_total: 68,
                    vt_malicious: 42,
                    anomalies: ["Unusual Outbound Burst", "C2 Communication Pattern"]
                }
            ];
            renderUI();
            showToast("SIMULATION ACTIVE", "Simulated traffic data injected for UI validation.", "info");
        }

        async function initSettings() {
            try {
                const response = await fetch('/api/settings', {
                    headers: { 'Authorization': `Bearer ${SESSION_TOKEN}` }
                });
                const json = await response.json();
                if (json.status === 'success') {
                    if (json.data.language) {
                        currentLang = json.data.language;
                        document.getElementById('current-lang').innerText = currentLang;
                        if (currentLang === 'AR') document.body.classList.add('rtl');
                        applyTranslations();
                    }
                    // Trigger Onboarding if First Run
                    if (json.data.first_run) {
                        setTimeout(runOnboarding, 1000);
                    }
                }
            } catch (e) { console.error("Settings load failed", e); }
        }

        function runOnboarding() {
            document.getElementById('modal-overlay').style.display = 'block';
            document.getElementById('onboarding-modal').style.display = 'flex';
        }

        function nextWiz(step) {
            document.querySelectorAll('.wizard-step').forEach(s => s.classList.remove('active'));
            document.getElementById(`wiz-step-${step}`).classList.add('active');
        }

        async function finishWiz() {
            document.getElementById('onboarding-modal').style.display = 'none';
            document.getElementById('modal-overlay').style.display = 'none';
            showToast("ONBOARDING COMPLETE", "System initialized and secured.", "info");

            // Persist completion
            await fetch('/api/settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${SESSION_TOKEN}`
                },
                body: JSON.stringify({ 'first_run_completed': true })
            });
        }

        try { initSettings(); } catch (e) { }
        try {
            if (typeof filterInput !== 'undefined' && filterInput) {
                // AGGRESSIVE ANTI-AUTOFILL
                function scrubAutofill() {
                    if (filterInput.value.toLowerCase() === 'admin' ||
                        filterInput.value.toLowerCase() === 'sentinel123' ||
                        filterInput.value.includes('****')) {
                        filterInput.value = '';
                        renderUI();
                    }
                }
                setInterval(scrubAutofill, 100);
                scrubAutofill();
                filterInput.addEventListener('input', renderUI);
            }
        } catch (e) { console.error("filter input error", e); }
        try { initMap(); } catch (e) { console.error("initMap error", e); }
        try { initChart(); } catch (e) { console.error("initChart error", e); }
        try { updateRadar(); setInterval(updateRadar, 2000); } catch (e) { console.error("radar loop error", e); }
        try { updatePackets(); setInterval(updatePackets, 1000); } catch (e) { console.error("packet loop error", e); }
        try { updateSwarm(); setInterval(updateSwarm, 10000); } catch (e) { console.error("swarm loop error", e); }
    