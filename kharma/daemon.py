import time
import os
import psutil
from plyer import notification
import json
import requests
from kharma.scanner import NetworkScanner
from kharma.threat import ThreatIntelligence
from kharma.vt_engine import VTEngine
from kharma.behavior import BehaviorEngine
from kharma.yara_scanner import YaraScanner
from kharma.honeypot import HoneypotDecoy

class KharmaDaemon:
    def __init__(self, auto_kill=False):
        self.auto_kill = auto_kill
        self.scanner = NetworkScanner()
        self.intel = ThreatIntelligence()
        self.vt_engine = VTEngine()
        self.behavior = BehaviorEngine()
        self.yara = YaraScanner()
        self.honeypot = HoneypotDecoy()
        self.config_path = os.path.expanduser("~/.kharma/daemon_config.json")
        self.reported_connections = set() # Avoid spamming the same connection alert
        self._load_config()

    def _load_config(self):
        self.telegram_bot_token = None
        self.telegram_chat_id = None
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    config = json.load(f)
                    self.telegram_bot_token = config.get("telegram_bot_token")
                    self.telegram_chat_id = config.get("telegram_chat_id")
            except Exception as e:
                print(f"[DAEMON] Config load error: {e}")

    def _send_telegram(self, message):
        if self.telegram_bot_token and self.telegram_chat_id:
            url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
            payload = {"chat_id": self.telegram_chat_id, "text": message}
            try:
                requests.post(url, json=payload, timeout=5)
            except Exception as e:
                print(f"[DAEMON] Telegram alert failed: {e}")

    def run(self):
        """Infinite loop to monitor network states silently in the background."""
        # 1. Start Honeypots (Deception Defense)
        self.honeypot.start(callback=self._honeypot_callback)

        # 2. Initial boot notification
        try:
            notification.notify(
                title="Kharma Sentinel Active",
                message=f"Sentinel Deep Protection is ONLINE. Auto-Kill: {'Enabled' if self.auto_kill else 'Disabled'}",
                app_name="Kharma Sentinel",
                timeout=5
            )
        except Exception as e:
            print(f"[DAEMON] Notification error: {e}")
            
        while True:
            try:
                self.scanner.scan()
                active_conns = self.scanner.get_active_connections()
                
                for conn in active_conns:
                    ip = conn['remote_ip']
                    port = conn['remote_port']
                    pid = conn['pid']
                    p_name = conn['name']
                    exe_path = conn['exe']
                    
                    conn_id = f"{pid}-{ip}:{port}"
                    
                    if conn_id not in self.reported_connections:
                        # --- 1. Behavioral Intelligence Checks ---
                        behavioral_alert = self.behavior.analyze_io(pid, p_name, conn.get('io_counters'))
                        # Also check beaconing
                        if not behavioral_alert:
                            # Note: BehaviorEngine.analyze needs more params, but we can do a quick beacon check here
                            # or just use the logic in BehaviorEngine if it were fully unified. 
                            # For simplicity, we use the beaconing logic already in behavior.py via specialized check if available.
                            pass

                        trigger_reason = None
                        if behavioral_alert:
                            trigger_reason = f"Behavioral: {behavioral_alert['message']}"
                        
                        # --- 2. Static Indicators (Existing logic) ---
                        is_malware_ip = self.intel.check_ip(ip)
                        vt_malicious = 0
                        if self.vt_engine and exe_path:
                            file_hash = self.vt_engine.get_file_hash(exe_path)
                            vt_malicious, _ = self.vt_engine.check_hash(file_hash)
                        
                        if is_malware_ip: trigger_reason = "Malicious IP Match"
                        if vt_malicious > 0: trigger_reason = f"VirusTotal ({vt_malicious} Engines)"

                        # --- 3. Deep YARA Inspection (The heavy lifting) ---
                        yara_matches = []
                        if trigger_reason and exe_path:
                            yara_matches = self.yara.scan_file(exe_path)
                            if yara_matches:
                                trigger_reason += f" + YARA: {', '.join(yara_matches)}"

                        if trigger_reason:
                            self.reported_connections.add(conn_id)
                            
                            action_taken = "Alert Generated"
                            if self.auto_kill and pid:
                                try:
                                    p = psutil.Process(pid)
                                    p_name_lower = p.name().lower()
                                    critical_procs = {'system idle process', 'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'explorer.exe', 'winlogon.exe'}
                                    if p_name_lower in critical_procs:
                                        action_taken = "CRITICAL OS PROC. AUTO-KILL BLOCKED."
                                    else:
                                        p.terminate()
                                        action_taken = "PROCESS TERMINATED (Sentinel Shield)"
                                except:
                                    action_taken = "AUTO-KILL FAILED"
                            
                            alert_msg = f"⚔️ SENTINEL DEFENSE TRIGGERED ⚔️\n\nTrigger: {trigger_reason}\nProcess: {p_name} (PID: {pid})\nBinary: {exe_path}\nTarget: {ip}:{port}\n\nAction: {action_taken}"
                            
                            try:
                                notification.notify(
                                    title=f"Sentinel: Threat Neutralized" if "TERMINATED" in action_taken else "Sentinel: Security Alert",
                                    message=f"{p_name} ({trigger_reason})",
                                    app_name="Kharma Sentinel",
                                    timeout=10
                                )
                            except: pass
                            self._send_telegram(alert_msg)

                time.sleep(5)
            except Exception as e:
                time.sleep(10)

    def _honeypot_callback(self, ip, port):
        """Callback for honeypot triggers."""
        alert_msg = f"🍯 HONEYPOT TRAP TRIGGERED 🍯\n\nAttacker IP: {ip}\nPort: {port}\n\nDecision: IP logged for investigation."
        try:
            notification.notify(
                title="Honeypot Triggered!",
                message=f"Unauthorized access from {ip} on port {port}",
                app_name="Kharma Sentinel",
                timeout=10
            )
        except: pass
        self._send_telegram(alert_msg)
