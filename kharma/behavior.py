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
        self.baseline_stats = self._load_baseline()
        # runtime_history: { process_name: [list of bandwidth samples] }
        self.runtime_history = defaultdict(list)
        # ip_history: { process_name: set(remote_ips) }
        self.ip_history = defaultdict(set)
        self.max_samples = 100
        self.last_save = time.time()

    def _load_baseline(self):
        if os.path.exists(self.BASELINE_PATH):
            try:
                with open(self.BASELINE_PATH, 'r') as f:
                    return json.load(f)
            except Exception as e:
                # Handle config directory creation errors
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

    def analyze(self, p_name, kb_in, kb_out, country_code):
        """
        Main entry point for server loop. Returns a dict of AI results.
        Previously returned a list of strings, now enhanced with numeric scoring.
        """
        current_vol = kb_in + kb_out
        self.runtime_history[p_name].append(current_vol)
        if len(self.runtime_history[p_name]) > self.max_samples:
            self.runtime_history[p_name].pop(0)

        # 1. Statistical Anomaly Calculation
        score = self._calculate_score(p_name, current_vol)
        
        # 2. Build Legacy "anomalies" list for compatibility
        anomalies = []
        level = "NORMAL"
        msg = "Behavior Normal"

        if score > 7.5:
            level = "CRITICAL"
            msg = "Extreme Network Spike"
            anomalies.append(f"AI Alert: Pattern Shift ({score})")
        elif score > 4.5:
            level = "SUSPICIOUS"
            msg = "Unusual Volatility"
            anomalies.append(f"AI: Abnormal Volume ({score})")
        
        # 3. Geo-Link baseline integration (legacy feature)
        # (This could be expanded later)

        # Periodic save
        if time.time() - self.last_save > 600:
            self._save_baseline()
            self.last_save = time.time()

        return {
            "score": score,
            "level": level,
            "message": msg,
            "anomalies": anomalies
        }

    def _calculate_score(self, p_name, current_vol):
        samples = self.runtime_history[p_name]
        
        # Try to use saved baseline first
        base = self.baseline_stats.get(p_name)
        if base and len(samples) < 20: # Use baseline until enough samples gathered
            avg = base['avg']
            std = base['std']
        elif len(samples) >= 10:
            avg = sum(samples) / len(samples)
            var = sum((x - avg) ** 2 for x in samples) / len(samples)
            std = math.sqrt(var) or 0.1
        else:
            return 0.0 # Learning...

        # Z-Score
        z = abs(current_vol - avg) / std
        return round(min(z * 1.2, 10.0), 2)
