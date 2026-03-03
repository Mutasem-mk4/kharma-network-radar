// KHARMA SENTINEL - Bootstrap & Main Loops

function initSettings() {
    fetchSettings().then(json => {
        if (json && json.status === 'success') {
            if (json.data.language) {
                currentLang = json.data.language;
                const langEl = document.getElementById('current-lang');
                if (langEl) langEl.innerText = currentLang;
                if (currentLang === 'AR') document.body.classList.add('rtl');
                if (typeof applyTranslations === 'function') applyTranslations();
            }
            if (json.data.first_run) {
                setTimeout(runOnboarding, 1000);
            }
        }
    });
}

function runOnboarding() {
    const overlay = document.getElementById('modal-overlay');
    const modal = document.getElementById('onboarding-modal');
    if (overlay) overlay.style.display = 'block';
    if (modal) modal.style.display = 'flex';
}

function finishWiz() {
    const overlay = document.getElementById('modal-overlay');
    const modal = document.getElementById('onboarding-modal');
    if (modal) modal.style.display = 'none';
    if (overlay) overlay.style.display = 'none';
    showToast("ONBOARDING COMPLETE", "System initialized and secured.", "info");

    saveSettings({ 'first_run_completed': true });
}

document.addEventListener('DOMContentLoaded', () => {
    // 1. Initialize State/State-dependent UI
    if (typeof lucide !== 'undefined') lucide.createIcons();

    // 2. Initialize Modules
    if (typeof initMap === 'function') initMap();
    if (typeof initChart === 'function') initChart();
    initSettings();

    // 3. Start Telemetry Worker
    try {
        window.telemetryWorker = new Worker('/static/telemetry-worker.js');
        window.telemetryWorker.onmessage = function (e) {
            if (e.data.type === 'TELEMETRY_READY') {
                window._telemetryReceived = true;
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

    // 4. Start Loops
    let radarTimer = null;
    function scheduleRadarUpdate() {
        if (radarTimer) return;
        radarTimer = setTimeout(() => { updateRadar(); radarTimer = null; }, 500);
    }
    let packetsTimer = null;
    function schedulePacketsUpdate() {
        if (packetsTimer) return;
        packetsTimer = setTimeout(() => { updatePackets(); packetsTimer = null; }, 300);
    }
    // Initial calls
    scheduleRadarUpdate();
    schedulePacketsUpdate();
    // Continuous loop using requestAnimationFrame for smoother updates
    function animationLoop() {
        scheduleRadarUpdate();
        schedulePacketsUpdate();
        requestAnimationFrame(animationLoop);
    }
    requestAnimationFrame(animationLoop);

    // Low frequency loops
    updateHistory();
    setInterval(updateHistory, 3000);

    if (typeof updateSwarm === 'function') {
        updateSwarm();
        setInterval(updateSwarm, 5000);
    }


});
