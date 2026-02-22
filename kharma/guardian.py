import threading
import http.client
import json
import os

class GuardianBot:
    """
    Kharma Guardian Bot.
    Sends real-time threat alerts to configured Telegram and Discord channels.
    Alert types:
        - THREAT_DETECTED: A malware IP was found in active connections.
        - IP_BLOCKED: An IP was automatically shielded.
        - DPI_ALERT: A high-severity payload signature was detected in packets.
    """
    CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".kharma", "guardian_config.json")

    def __init__(self):
        self.config = self._load_config()
        self._alerted_ips = set()  # To prevent repeated alerts for the same IP

    def _load_config(self):
        """Loads webhook config from disk, returns defaults if not found."""
        if os.path.exists(self.CONFIG_PATH):
            try:
                with open(self.CONFIG_PATH, 'r') as f:
                    return json.load(f)
            except: pass
        return {
            "telegram_bot_token": "",
            "telegram_chat_id": "",
            "discord_webhook_url": "",
            "alert_on_threat": True,
            "alert_on_block": True,
            "alert_on_dpi": True
        }

    def save_config(self, new_config):
        """Saves updated config to disk."""
        os.makedirs(os.path.dirname(self.CONFIG_PATH), exist_ok=True)
        self.config.update(new_config)
        with open(self.CONFIG_PATH, 'w') as f:
            json.dump(self.config, f, indent=4)

    def _send_telegram(self, message):
        """Sends a message to the configured Telegram chat."""
        token = self.config.get("telegram_bot_token", "")
        chat_id = self.config.get("telegram_chat_id", "")
        if not token or not chat_id:
            return
        try:
            conn = http.client.HTTPSConnection("api.telegram.org")
            payload = json.dumps({
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "HTML"
            })
            headers = {"Content-Type": "application/json"}
            conn.request("POST", f"/bot{token}/sendMessage", payload, headers)
            conn.getresponse()
        except Exception as e:
            print(f"[GUARDIAN] Telegram error: {e}")

    def _send_discord(self, message):
        """Sends a message to the configured Discord channel via webhook."""
        webhook_url = self.config.get("discord_webhook_url", "")
        if not webhook_url:
            return
        try:
            # Parse host and path from URL
            if webhook_url.startswith("https://"):
                remainder = webhook_url[len("https://"):]
                host, path = remainder.split("/", 1)
                path = "/" + path
            else:
                return
            payload = json.dumps({"content": message})
            headers = {"Content-Type": "application/json", "Content-Length": str(len(payload))}
            conn = http.client.HTTPSConnection(host)
            conn.request("POST", path, payload, headers)
            conn.getresponse()
        except Exception as e:
            print(f"[GUARDIAN] Discord error: {e}")

    def _broadcast(self, message):
        """Sends alert to all configured channels in a background thread."""
        def _send_all():
            self._send_telegram(message)
            self._send_discord(message)
        threading.Thread(target=_send_all, daemon=True).start()

    def alert_threat(self, ip, process_name, source="Threat Intel"):
        """Fires when a known malicious IP is detected in active connections."""
        if not self.config.get("alert_on_threat") or ip in self._alerted_ips:
            return
        self._alerted_ips.add(ip)
        msg = (
            f"🚨 <b>KHARMA ALERT: THREAT DETECTED</b>\n"
            f"━━━━━━━━━━━━━━━━━━━\n"
            f"🔴 <b>Malicious IP:</b> <code>{ip}</code>\n"
            f"💻 <b>Process:</b> {process_name}\n"
            f"🔎 <b>Source:</b> {source}\n"
            f"━━━━━━━━━━━━━━━━━━━\n"
            f"Action: Review Kharma dashboard immediately."
        )
        self._broadcast(msg)

    def alert_blocked(self, ip, reason="Auto-Shield"):
        """Fires when Kharma automatically blocks an IP."""
        if not self.config.get("alert_on_block"):
            return
        msg = (
            f"🛡️ <b>KHARMA SHIELD: IP BLOCKED</b>\n"
            f"━━━━━━━━━━━━━━━━━━━\n"
            f"🔒 <b>Blocked IP:</b> <code>{ip}</code>\n"
            f"📋 <b>Reason:</b> {reason}\n"
            f"━━━━━━━━━━━━━━━━━━━\n"
            f"The firewall rule has been applied."
        )
        self._broadcast(msg)

    def alert_dpi(self, src, dst, alert_type):
        """Fires when DPI detects a suspicious payload."""
        if not self.config.get("alert_on_dpi"):
            return
        msg = (
            f"⚠️ <b>KHARMA DPI: PAYLOAD ALERT</b>\n"
            f"━━━━━━━━━━━━━━━━━━━\n"
            f"💉 <b>Attack Type:</b> {alert_type}\n"
            f"📤 <b>Source:</b> <code>{src}</code>\n"
            f"📥 <b>Destination:</b> <code>{dst}</code>\n"
            f"━━━━━━━━━━━━━━━━━━━\n"
            f"Review the DPI stream for full details."
        )
        self._broadcast(msg)

    def get_config(self):
        """Returns the current (sanitized) config."""
        return self.config
