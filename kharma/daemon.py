import time
import os
import psutil
from plyer import notification
import json
import requests
from kharma.scanner import NetworkScanner
from kharma.threat import ThreatIntelligence

class KharmaDaemon:
    def __init__(self, auto_kill=False):
        self.auto_kill = auto_kill
        self.scanner = NetworkScanner()
        self.intel = ThreatIntelligence()
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
            except Exception:
                pass

    def _send_telegram(self, message):
        if self.telegram_bot_token and self.telegram_chat_id:
            url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
            payload = {"chat_id": self.telegram_chat_id, "text": message}
            try:
                requests.post(url, json=payload, timeout=5)
            except Exception:
                pass

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
        except Exception:
            pass # Fails gracefully if OS doesn't support toast notifications natively
            
        while True:
            try:
                self.scanner.scan()
                for conn in self.scanner.connections:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        ip = conn.raddr.ip
                        port = conn.raddr.port
                        if ip in ('127.0.0.1', '::1', '0.0.0.0'):
                            continue
                            
                        conn_id = f"{conn.pid}-{ip}:{port}"
                        
                        # Only alert once per active connection instance
                        if conn_id not in self.reported_connections:
                            if self.intel.check_ip(ip):
                                self.reported_connections.add(conn_id)
                                p_name = self.scanner.process_names.get(conn.pid, "Unknown")
                                
                                action_taken = "Alert Generated (No Protection enabled)"
                                if self.auto_kill and conn.pid:
                                    try:
                                        psutil.Process(conn.pid).terminate()
                                        action_taken = "PROCESS TERMINATED (IPS Triggered)"
                                    except Exception as e:
                                        action_taken = f"AUTO-KILL FAILED ({e})"
                                
                                alert_msg = f"🚨 KHARMA SECURITY ALERT 🚨\n\nMalware Connection Detected!\nProcess: {p_name} (PID: {conn.pid})\nDestination: {ip}:{port}\n\nAction Taken: {action_taken}"
                                
                                # Send Desktop Toast Notification
                                try:
                                    notification.notify(
                                        title="Kharma Malware Alert",
                                        message=f"{p_name} connected to malicious IP {ip}. {action_taken}",
                                        app_name="Kharma Radar",
                                        timeout=10
                                    )
                                except Exception:
                                    pass
                                    
                                # Send Telegram Webhook Alert
                                self._send_telegram(alert_msg)
                
                # Check every 5 seconds to minimize CPU footprint
                time.sleep(5)
            except Exception:
                time.sleep(10) # Fallback to prevent rapid crash loops
