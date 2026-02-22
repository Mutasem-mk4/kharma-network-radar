import psutil
import os
import re
import time
import hashlib

class HunterEngine:
    """
    Kharma Threat Hunter — Deep Process Forensics.
    Extracts metadata, strings, and heuristics from live processes.
    """
    
    def get_process_details(self, pid):
        """Returns comprehensive forensic data for a PID."""
        try:
            p = psutil.Process(pid)
            with p.once_hidden():
                info = p.as_dict(attrs=[
                    'pid', 'name', 'exe', 'cmdline', 'create_time', 
                    'status', 'username', 'num_threads', 'cpu_percent'
                ])
                
                # Extended Forensic Data
                info['parent_pid'] = p.parent().pid if p.parent() else None
                info['memory_info'] = p.memory_info()._asdict()
                
                # File Handles (requires privilege)
                try:
                    info['open_files'] = [f.path for f in p.open_files()]
                except:
                    info['open_files'] = ["Access Denied"]
                
                # Heuristic Flags
                info['heuristics'] = self._analyze_heuristics(p, info)
                
                # Binary Strings (First 100)
                info['strings'] = self._extract_strings(info['exe'])
                
                return {"status": "success", "data": info}
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {"status": "error", "message": str(e)}

    def _analyze_heuristics(self, p, info):
        """Simple rule-based heuristic engine."""
        flags = []
        exe_path = info.get('exe', '').lower()
        cmdline = " ".join(info.get('cmdline', [])).lower()
        
        # 1. Path Heuristics
        suspicious_paths = ['temp', 'appdata', 'public', 'downloads']
        if any(sp in exe_path for sp in suspicious_paths):
            flags.append(f"Suspicious Path: running from {exe_path}")
            
        # 2. Name Masquerading
        if info['name'].lower() in ['svchost.exe', 'lsass.exe'] and 'system32' not in exe_path:
            flags.append("Masquerading: System process outside System32")
            
        # 3. Command Line Heuristics
        shady_args = ['-enc', 'hidden', 'bypass', 'nop', 'downloadstring', 'curl', 'wget']
        if any(sa in cmdline for sa in shady_args):
            flags.append("Suspicious Arguments: Scripting/Bypass flags detected")
            
        return flags

    def _extract_strings(self, exe_path, limit=100):
        """Extracts readable ASCII and UTF-16 strings from the binary."""
        if not exe_path or not os.path.exists(exe_path):
            return []
            
        strings = []
        try:
            # We only scan the first 1MB to keep it fast
            with open(exe_path, "rb") as f:
                data = f.read(1024 * 1024)
                
            # ASCII pattern
            ascii_strings = re.findall(b"[ -~]{6,}", data)
            for s in ascii_strings:
                try:
                    strings.append(s.decode('ascii'))
                except: pass
                if len(strings) >= limit: break
        except:
            pass
        return strings[:limit]
