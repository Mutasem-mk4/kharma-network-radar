import json
import os
import time
from collections import defaultdict

class BehaviorEngine:
    """
    Kharma Behavioral Profiling — Detects anomalies based on history.
    Tracks:
        - Connection Frequency (conn/sec)
        - Data Volume (KB/sec)
        - Geographic Footprint (Unique Countries)
    """
    BASELINE_PATH = os.path.join(os.path.expanduser("~"), ".kharma", "behavior_baseline.json")

    def __init__(self):
        self.baseline = self._load_baseline()
        # session_data: { process_name: { 'last_seen': T, 'conn_count': N, 'total_in': B, 'total_out': B } }
        self.session_data = defaultdict(lambda: {"conn_count": 0, "total_in": 0, "total_out": 0, "start_time": time.time()})

    def _load_baseline(self):
        if os.path.exists(self.BASELINE_PATH):
            try:
                with open(self.BASELINE_PATH, 'r') as f:
                    return json.load(f)
            except: pass
        return {}

    def _save_baseline(self):
        os.makedirs(os.path.dirname(self.BASELINE_PATH), exist_ok=True)
        with open(self.BASELINE_PATH, 'w') as f:
            json.dump(self.baseline, f, indent=4)

    def analyze(self, process_name, current_in, current_out, country_code):
        """Analyzes behavior and returns a list of anomalies."""
        p_base = self.baseline.get(process_name, {})
        anomalies = []
        
        # 1. Update Session Counters
        s_data = self.session_data[process_name]
        s_data["conn_count"] += 1
        s_data["total_in"] += current_in
        s_data["total_out"] += current_out
        
        # 2. Check for "New Territory"
        known_countries = p_base.get("countries", [])
        if country_code and country_code != "LOCAL" and country_code not in known_countries:
            anomalies.append(f"Unusual Geo-Link: {country_code}")
            # Update baseline (auto-learning for now)
            if country_code not in known_countries:
                known_countries.append(country_code)
                p_base["countries"] = known_countries
        
        # 3. Check for Volume Spikes (if baseline exists)
        avg_vol = p_base.get("avg_kbps", 0)
        current_vol = current_in + current_out
        if avg_vol > 10 and current_vol > (avg_vol * 10): # 10x spike
            anomalies.append(f"Volume Spike: {current_vol:.1f} KB/s vs {avg_vol:.1f} base")

        # 4. Periodically Update Baseline (Smoothing)
        now = time.time()
        if now - s_data["start_time"] > 60: # Every minute
            duration = now - s_data["start_time"]
            kbps = (s_data["total_in"] + s_data["total_out"]) / duration
            
            # Weighted average for smoothing
            old_avg = p_base.get("avg_kbps", kbps)
            new_avg = (old_avg * 0.7) + (kbps * 0.3)
            p_base["avg_kbps"] = round(new_avg, 2)
            
            self.baseline[process_name] = p_base
            self._save_baseline()
            
            # Reset session counters
            s_data["start_time"] = now
            s_data["total_in"] = 0
            s_data["total_out"] = 0
            
        return anomalies
