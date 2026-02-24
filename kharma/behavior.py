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

    def _calculate_baseline(self): # Internal helper renaming
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
        if not data:
            return 0.0
        if isinstance(data, str):
            data = data.encode('utf-8', errors='ignore')
        
        entropy = 0
        freq = defaultdict(int)
        for b in data:
            freq[b] += 1
            
        data_len = len(data)
        for count in freq.values():
            p = count / data_len
            entropy -= p * math.log2(p)
            
        return round(entropy, 2)

    def analyze(self, p_name, kb_in, kb_out, country_code, payload=None):
        """
        Main entry point for server loop. Returns a dict of AI results.
        Enhanced with Shannon Entropy analysis for payload randomization check.
        """
        current_vol = kb_in + kb_out
        self.runtime_history[p_name].append(current_vol)
        if len(self.runtime_history[p_name]) > self.max_samples:
            self.runtime_history[p_name].pop(0)

        # 1. Statistical Anomaly Calculation (Z-Score)
        score = self._calculate_score(p_name, current_vol)
        
        # 2. Entropy Analysis (Randomness Detection)
        entropy_score = 0.0
        if payload:
            entropy = self._calculate_entropy(payload)
            # High entropy (> 7.0 for bytes) often indicates encrypted/compressed data
            if entropy > 7.2:
                entropy_score = 5.0 # High suspicion
            elif entropy > 6.5:
                entropy_score = 2.0
            score += entropy_score

        # 3. Build anomalies list
        anomalies = []
        level = "NORMAL"
        msg = "Behavior Normal"

        if score > 8.5:
            level = "CRITICAL"
            msg = "Extreme Network/Payload Anomaly"
            anomalies.append(f"Sentinel Alert: High Entropy + Volume ({score})")
        elif score > 5.5:
            level = "SUSPICIOUS"
            msg = "Unusual Volatility or Encrypted Tunnel"
            anomalies.append(f"Sentinel: Behavioral Pattern Shift ({score})")
        
        if entropy_score > 0:
            anomalies.append(f"AI: High Payload Entropy detected ({entropy})")
        
        # 4. Burst Detection
        if len(samples) >= 3:
            recent_growth = samples[-1] / (samples[-2] + 0.1)
            if recent_growth > 50 and samples[-1] > 100: # 50x growth and > 100KB
                anomalies.append(f"AI: Data Burst Detected ({round(recent_growth, 1)}x)")
                score += 3.0
        
        # 5. Domain Pattern Heuristics (Simple)
        if p_name.lower() in ['nslookup.exe', 'dig.exe', 'powershell.exe'] and kb_out > kb_in:
            anomalies.append("AI: Potential DNS Exfiltration Pattern")
            score += 4.0

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
