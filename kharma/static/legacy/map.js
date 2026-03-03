// KHARMA SENTINEL - Map Management Module (Leaflet)

function initMap() {
    const mapEl = document.getElementById('radar-map');
    if (!mapEl) return;

    globe = L.map('radar-map', {
        zoomControl: false,
        attributionControl: false,
        worldCopyJump: true
    }).setView([myLat, myLon], 3);

    const labelPane = globe.createPane('labels');
    labelPane.style.zIndex = 650;
    labelPane.style.pointerEvents = 'none';

    L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/dark_nolabels/{z}/{x}/{y}{r}.png', {
        maxZoom: 19,
        attribution: '&copy; OpenStreetMap &copy; CARTO'
    }).addTo(globe);

    L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/dark_only_labels/{z}/{x}/{y}{r}.png', {
        maxZoom: 19,
        pane: 'labels',
        opacity: 0.8
    }).addTo(globe);

    window._mapMarkers = L.layerGroup().addTo(globe);
    window._mapArcs = L.layerGroup().addTo(globe);
    window._markerCache = new Map();
    window._arcCache = new Map();

    L.circleMarker([myLat, myLon], {
        radius: 7,
        fillColor: "var(--accent)",
        color: "#fff",
        weight: 2,
        opacity: 1,
        fillOpacity: 0.9
    }).addTo(globe).bindTooltip("<b style='color:var(--accent)'>LOCAL SENSOR HUB</b><br/>ACTIVE MONITORING", { permanent: false, direction: 'top' });

    setTimeout(() => { if (globe) globe.invalidateSize(); }, 800);
}

function updateMapTelemetry() {
    if (!globe) return;
    const currentLocations = new Map();
    const now = Date.now();
    const MARKER_TTL = 10000; // 10 seconds of persistence

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
        const conn = conns[0];
        const count = conns.length;
        const hasThreat = conns.some(c => c.is_malware || c.ai_score > 7);
        const hasFlag = conns.some(c => c.is_community_flagged);
        const hasShield = conns.some(c => c.is_shielded);

        let color = "#10b981";
        if (hasShield) color = "#6366f1";
        if (hasFlag && !hasThreat) color = "#f59e0b";
        if (hasThreat) color = "var(--danger)";

        // Shortest Path Longitude Logic (Antimeridian Wrapping)
        let targetLon = conn.lon;
        if (Math.abs(targetLon - myLon) > 180) {
            if (targetLon > myLon) targetLon -= 360;
            else targetLon += 360;
        }

        if (window._markerCache.has(locKey)) {
            const entry = window._markerCache.get(locKey);
            entry.marker.setLatLng([conn.lat, conn.lon]);
            entry.marker.setStyle({
                fillColor: color,
                radius: count > 1 ? 8 : 5,
                className: hasThreat ? 'pulse-marker-2d' : '',
                fillOpacity: 0.8,
                opacity: 1
            });
            entry.marker.setTooltipContent(getTacticalInfoHtml(conns, color, count));
            entry.lastSeen = now;
        } else {
            const marker = L.circleMarker([conn.lat, conn.lon], {
                radius: count > 1 ? 8 : 5,
                fillColor: color,
                color: "#fff",
                weight: 1,
                opacity: 1,
                fillOpacity: 0.8,
                className: hasThreat ? 'pulse-marker-2d' : ''
            }).bindTooltip(getTacticalInfoHtml(conns, color, count));
            window._mapMarkers.addLayer(marker);
            window._markerCache.set(locKey, { marker: marker, lastSeen: now });
        }

        if (window._arcCache.has(locKey)) {
            const entry = window._arcCache.get(locKey);
            entry.arc.setLatLngs([[myLat, myLon], [conn.lat, targetLon]]);
            entry.arc.setStyle({ color: color, opacity: 0.1 });
            entry.lastSeen = now;
        } else {
            const arc = L.polyline([[myLat, myLon], [conn.lat, targetLon]], {
                color: color,
                weight: 1,
                opacity: 0.1,
                dashArray: '20, 20',
                className: 'tactical-arc'
            });
            window._mapArcs.addLayer(arc);
            window._arcCache.set(locKey, { arc: arc, lastSeen: now });
        }
    });

    // Cleanup & Decay Logic
    window._markerCache.forEach((entry, locKey) => {
        const age = now - entry.lastSeen;
        if (age > MARKER_TTL) {
            window._mapMarkers.removeLayer(entry.marker);
            window._markerCache.delete(locKey);
        } else if (age > 1000) {
            // Start fading after 1 second of inactivity
            const fadeFactor = 1 - (age / MARKER_TTL);
            entry.marker.setStyle({ fillOpacity: 0.8 * fadeFactor, opacity: fadeFactor });
        }
    });

    window._arcCache.forEach((entry, locKey) => {
        const age = now - entry.lastSeen;
        if (age > MARKER_TTL) {
            window._mapArcs.removeLayer(entry.arc);
            window._arcCache.delete(locKey);
        } else if (age > 1000) {
            const fadeFactor = 1 - (age / MARKER_TTL);
            entry.arc.setStyle({ opacity: 0.3 * fadeFactor });
        }
    });
}

function getTacticalInfoHtml(conns, color, count) {
    const conn = conns[0];
    return `
        <div style="padding: 4px; font-family: 'JetBrains Mono', monospace;">
            <b style="color:${color}">${count > 1 ? `[CLUSTER] ${count} FLOWS` : conn.process_name}</b><br/>
            <span style="font-size:0.65rem; color:var(--text-dim);">${conn.location}</span><br/>
            ${conns.slice(0, 3).map(c => `<div style="font-size:0.6rem; border-top:1px solid rgba(255,255,255,0.1); margin-top:2px;">• ${c.remote_ip}</div>`).join('')}
            ${count > 3 ? `<div style="font-size:0.6rem; color:var(--accent);">+ ${count - 3} more...</div>` : ''}
        </div>
    `;
}
