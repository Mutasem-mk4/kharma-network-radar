// Kharma Sentinel - Telemetry Web Worker
// Handles heavy JSON parsing, sorting, and filtering off the main thread.

self.onmessage = function (e) {
    const { type, data, filter } = e.data;

    if (type === 'PROCESS_TELEMETRY') {
        let processed = data;

        // 1. High-speed Filtering
        if (filter) {
            const f = filter.toLowerCase();
            processed = data.filter(conn =>
                conn.process_name.toLowerCase().includes(f) ||
                conn.remote_ip.includes(f) ||
                (conn.location && conn.location.toLowerCase().includes(f)) ||
                conn.pid.toString().includes(f)
            );
        }

        // 2. Tactical Sorting (Threats First, then AI Score, then PID for stability)
        processed.sort((a, b) => {
            if (a.is_malware !== b.is_malware) return a.is_malware ? -1 : 1;
            if (a.ai_score !== b.ai_score) return b.ai_score - a.ai_score;
            return b.pid - a.pid; // Stable fallback
        });

        // Send back to main thread
        self.postMessage({
            type: 'TELEMETRY_READY',
            data: processed
        });
    }
};
