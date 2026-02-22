import threading
from collections import deque
import time

# Try to import scapy — requires Npcap on Windows
try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

class DPIEngine:
    """
    Advanced Deep Packet Inspection (DPI) Engine for Kharma.
    Requires Npcap (Windows) or libpcap (Linux) to be installed.
    Falls back gracefully if the driver is not available.
    """
    def __init__(self, max_buffer=50):
        self.packet_buffer = deque(maxlen=max_buffer)
        self.is_running = False
        self.thread = None
        self.available = SCAPY_AVAILABLE
        
        # Signatures for common web attacks
        self.signatures = {
            "SQL Injection": [b"SELECT", b"UNION", b"INSERT", b"UPDATE", b"DELETE", b"DROP TABLE"],
            "XSS / Web Shell": [b"<script>", b"eval(", b"base64_decode", b"system(", b"passthru("],
            "RFI / Path Traversal": [b"etc/passwd", b"boot.ini"],
            "Suspicious String": [b"cmd.exe", b"/bin/sh", b"powershell"]
        }

    def start(self):
        """Starts the packet sniffer in a background thread (requires Npcap on Windows)."""
        if not self.available:
            print("[DPI] Npcap/libpcap not found. Packet sniffing disabled. Install Npcap from https://npcap.com")
            return
        if not self.is_running:
            self.is_running = True
            self.thread = threading.Thread(target=self._sniffer_loop, daemon=True)
            self.thread.start()

    def stop(self):
        """Stops the sniffing thread."""
        self.is_running = False

    def _sniffer_loop(self):
        """Internal loop to capture packets using Scapy."""
        try:
            while self.is_running:
                sniff(prn=self._process_packet, count=5, timeout=1, store=0)
        except Exception as e:
            print(f"[DPI] Sniffer stopped: {e}")
            self.is_running = False
            self.available = False

    def _process_packet(self, pkt):
        """Entry point for every captured packet."""
        if not pkt.haslayer(IP):
            return

        summary = {
            "time": time.strftime('%H:%M:%S'),
            "src": pkt[IP].src,
            "dst": pkt[IP].dst,
            "proto": "IP",
            "info": "",
            "severity": "info",
            "alert": None
        }

        # Protocol Detection
        if pkt.haslayer(TCP):
            summary["proto"] = "TCP"
            summary["info"] = f"PORT {pkt[TCP].dport} -> seq:{pkt[TCP].seq}"
        elif pkt.haslayer(UDP):
            summary["proto"] = "UDP"
            if pkt.haslayer(DNS):
                summary["proto"] = "DNS"
                if pkt[DNS].qd:
                    summary["info"] = f"Query: {pkt[DNS].qd.qname.decode(errors='ignore')[:30]}"
            else:
                summary["info"] = f"PORT {pkt[UDP].dport}"

        # Deep Inspection (Payload Scan)
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            # Attempt to decode as string if it looks like HTTP/Text
            try:
                text_payload = payload.decode('utf-8', errors='ignore')
                if "HTTP" in text_payload:
                    summary["proto"] = "HTTP"
                    first_line = text_payload.split('\n')[0].strip()
                    summary["info"] = first_line[:50]
            except:
                pass

            # Signature Matching
            for alert_name, patterns in self.signatures.items():
                for p in patterns:
                    if p in payload:
                        summary["severity"] = "danger"
                        summary["alert"] = alert_name
                        break
                if summary["alert"]: break

        self.packet_buffer.append(summary)

    def get_packets(self):
        """Returns the current buffer of analyzed packets."""
        return list(self.packet_buffer)
