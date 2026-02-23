import time
import os
import psutil
from plyer import notification
import json
import requests
from kharma.scanner import NetworkScanner
from kharma.threat import ThreatIntelligence
from kharma.vt_engine import VTEngine

class KharmaDaemon:
    def __init__(self, auto_kill=False):
        self.auto_kill = auto_kill
        self.scanner = NetworkScanner()
        self.intel = ThreatIntelligence()
        self.vt_engine = VTEngine()
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
        # Initial boot notification
        try:
            notification.notify(
                title="Kharma Daemon Started",
                message=f"Background Monitoring is Active. Auto-Kill: {'Enabled' if self.auto_kill else 'Disabled'}",
                app_name="Kharma Radar",
                timeout=5
            )
        except Exception as e:
            # Fails gracefully if OS doesn't support toast notifications natively
            # but we log it for visibility
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
                    
                    # Only alert once per active connection instance
                    if conn_id not in self.reported_connections:
                        is_malware_ip = self.intel.check_ip(ip)
                        vt_malicious = 0
                        
                        if self.vt_engine and exe_path:
                            file_hash = self.vt_engine.get_file_hash(exe_path)
                            malicious, _ = self.vt_engine.check_hash(file_hash)
                            if malicious and malicious > 0:
                                vt_malicious = malicious
                        
                        if is_malware_ip or vt_malicious > 0:
                            self.reported_connections.add(conn_id)
                            
                            trigger_source = "Network Threat Intel" if is_malware_ip else f"VirusTotal ({vt_malicious} Engines)"
                            action_taken = "Alert Generated (No Protection enabled)"
                            
                            if self.auto_kill and pid:
                                try:
                                    psutil.Process(pid).terminate()
                                    action_taken = "PROCESS TERMINATED (IPS Triggered)"
                                except Exception as e:
                                    action_taken = f"AUTO-KILL FAILED ({e})"
                            
                            alert_msg = f"🚨 KHARMA SECURITY ALERT 🚨\n\nMalware Connection Detected!\nTrigger: {trigger_source}\nProcess: {p_name} (PID: {pid})\nDestination: {ip}:{port}\n\nAction Taken: {action_taken}"
                            
                            # Send Desktop Toast Notification
                            try:
                                notification.notify(
                                    title="Kharma Malware Alert",
                                    message=f"{p_name} caught by {trigger_source}. {action_taken}",
                                    app_name="Kharma Radar",
                                    timeout=10
                                )
                            except Exception as e:
                                print(f"[DAEMON] Notification alert error: {e}")
                                
                            # Send Telegram Webhook Alert
                            self._send_telegram(alert_msg)
                
                # Check every 5 seconds to minimize CPU footprint
                time.sleep(5)
            except Exception:
                time.sleep(10) # Fallback to prevent rapid crash loops
