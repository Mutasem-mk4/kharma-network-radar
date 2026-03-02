import json
import os
import time
import math
from collections import defaultdict

class BehaviorEngine:
    """
    Kharma Elite AI Behavior Engine (Phase 24)
    Refined for per-connection analysis within the server loop.
    """
    BASELINE_PATH = os.path.join(os.path.expanduser("~"), ".kharma", "ai_baseline.json")

    def __init__(self):
        self.last_io_time = {} # pid -> last_update_time
        self.baseline_stats = self._load_baseline()
        # runtime_history: { process_name: [list of bandwidth samples] }
        self.runtime_history = defaultdict(list)
        # timing_history: { conn_id: [timestamps] }
        self.timing_history = defaultdict(list)
        # ip_history: { process_name: set(remote_ips) }
        self.ip_history = defaultdict(set)
        self.max_samples = 100
        self.last_save = time.time()
        # Exfiltration tracking
        self.io_history = defaultdict(lambda: {'last_bytes': 0})
        # Variance-based Beaconing
        self.variance_limit = 0.5

    def _load_baseline(self):
        if os.path.exists(self.BASELINE_PATH):
            try:
                with open(self.BASELINE_PATH, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[BEHAVIOR] Profile path error: {e}")
        return {}

    def _save_baseline(self):
        os.makedirs(os.path.dirname(self.BASELINE_PATH), exist_ok=True)
        summary = {}
        for p_name, samples in self.runtime_history.items():
            if len(samples) < 10: continue
            avg = sum(samples) / len(samples)
            var = sum((x - avg) ** 2 for x in samples) / len(samples)
            summary[p_name] = {"avg": avg, "std": math.sqrt(var) or 0.1}
        with open(self.BASELINE_PATH, 'w') as f:
            json.dump(summary, f, indent=4)

    def _calculate_entropy(self, data):
        """Calculates Shannon Entropy of a data block (bytes or string)."""
        if not data: return 0.0
        if isinstance(data, str): data = data.encode('utf-8', errors='ignore')
        freq = defaultdict(int)
        for b in data: freq[b] += 1
        data_len = len(data)
        entropy = 0
        for count in freq.values():
            p = count / data_len
            entropy -= p * math.log2(p)
        return round(entropy, 2)

    def analyze(self, p_name, kb_in, kb_out, remote_ip, country_code, payload=None):
        """
        Main entry point for server loop. Returns a dict of AI results.
        Implements Pattern-Match Heuristics (Phase 7.2).
        """
        # Whitelist local/loopback/catch-all IPs to prevent false positive behavioral alarms
        local_ips = ['0.0.0.0', '127.0.0.1', 'localhost', '::1', '*']
        if remote_ip in local_ips or remote_ip.startswith('192.168.') or remote_ip.startswith('10.'):
             return {
                "score": 0.0,
                "level": "SAFE",
                "message": "Local Network (Trusted)",
                "anomalies": [],
                "entropy": 0.0
            }
        
        current_vol = kb_in + kb_out
        self.runtime_history[p_name].append(current_vol)
        if len(self.runtime_history[p_name]) > self.max_samples:
            self.runtime_history[p_name].pop(0)

        conn_id = f"{p_name}_{remote_ip}"
        self.timing_history[conn_id].append(time.time())
        if len(self.timing_history[conn_id]) > 10:
            self.timing_history[conn_id].pop(0)

        # 1. Statistical Anomaly Calculation (Z-Score)
        score = self._calculate_score(p_name, current_vol)
        
        # 2. Entropy Analysis (Randomness Detection)
        entropy = self._calculate_entropy(payload) if payload else 0.0
        
        anomalies = []
        
        # --- PATTERN 1: C2 Beacon Detection (Heartbeat) ---
        if len(self.timing_history[conn_id]) >= 5:
            intervals = []
            ts = self.timing_history[conn_id]
            for i in range(1, len(ts)):
                intervals.append(ts[i] - ts[i-1])
            
            avg_int = sum(intervals) / len(intervals)
            variance = sum((x - avg_int) ** 2 for x in intervals) / len(intervals)
            if variance < 0.5 and avg_int > 2.0: # Very stable rhythm
                anomalies.append(f"AI: C2 Beacon Pattern Detected ({round(avg_int,1)}s interval)")
                score += 5.0

        # --- PATTERN 2: Data Exfiltration (Outbound heavy + High Entropy) ---
        if kb_out > 50 and kb_out > (kb_in * 10) and entropy > 7.0:
            anomalies.append("AI: Suspicious Outbound Payload (Exfiltration Pattern)")
            score += 6.0

        # --- PATTERN 3: Lateral Movement / Port Scanning ---
        self.ip_history[p_name].add(remote_ip)
        if len(self.ip_history[p_name]) > 15:
            anomalies.append(f"AI: High Fan-out Pattern ({len(self.ip_history[p_name])} Unique IPs)")
            score += 4.0

        # --- PATTERN 4: Known Dangerous Tooling ---
        suspicious_procs = ['powershell.exe', 'cmd.exe', 'nslookup.exe', 'certutil.exe', 'bitsadmin.exe', 'nc.exe']
        if p_name.lower() in suspicious_procs:
            if kb_out > 20: 
                anomalies.append(f"AI: Living-off-the-land Tooling Activity ({p_name})")
                score += 3.0

        # Final Verdict
        level = "SAFE"
        if score > 8.5: level = "CRITICAL"
        elif score > 6.5: level = "HIGH"
        elif score > 4.0: level = "SUSPICIOUS"
        elif score > 2.0: level = "ELEVATED"

        return {
            "score": round(min(score, 10.0), 2),
            "level": level,
            "message": "Heuristic Scan Complete",
            "anomalies": anomalies,
            "entropy": entropy
        }

    def get_io_kbps(self, pid, current_io):
        """Calculates KBps from direct system IO counters."""
        now = time.time()
        last_stats = self.io_history.get(pid)
        last_time = self.last_io_time.get(pid)
        
        kbps = {"in_kbps": 0.0, "out_kbps": 0.0}
        if last_stats and last_time:
            delta = now - last_time
            if delta > 0.1: # At least 100ms
                in_diff = current_io.read_bytes - last_stats.get('last_read_bytes', 0)
                out_diff = current_io.write_bytes - last_stats.get('last_bytes', 0)
                kbps['in_kbps'] = round((in_diff / 1024) / delta, 2)
                kbps['out_kbps'] = round((out_diff / 1024) / delta, 2)
        
        # Update trackers
        self.io_history[pid]['last_read_bytes'] = current_io.read_bytes
        self.io_history[pid]['last_bytes'] = current_io.write_bytes
        self.last_io_time[pid] = now
        return kbps

    def analyze_io(self, pid, name, current_io):
        """Detects exfiltration bursts via direct IO counters (Daemon support)."""
        if not current_io: return None
        last_stats = self.io_history[pid]
        current_bytes = current_io.write_bytes
        if last_stats['last_bytes'] > 0:
            delta_mb = (current_bytes - last_stats['last_bytes']) / (1024 * 1024)
            if delta_mb > 10.0: # 10MB/sec spike
                return {"score": 9.0, "level": "CRITICAL", "message": f"IO Spike: {delta_mb:.1f}MB written by {name}"}
        self.io_history[pid]['last_bytes'] = current_bytes
        return None

    def _calculate_score(self, p_name, current_vol):
        samples = self.runtime_history[p_name]
        base = self.baseline_stats.get(p_name)
        if base and len(samples) < 20:
            avg, std = base['avg'], base['std']
        elif len(samples) >= 10:
            avg = sum(samples) / len(samples)
            var = sum((x - avg) ** 2 for x in samples) / len(samples)
            std = math.sqrt(var) or 0.1
        else:
            return 0.0
        z = abs(current_vol - avg) / std
        return round(min(z * 1.2, 10.0), 2)
