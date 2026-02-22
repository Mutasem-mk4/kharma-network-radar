import threading
import time
from collections import deque, defaultdict

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
        
        # Bandwidth Tracking
        self.flow_map = {} # (ip, port) -> pid
        self.bandwidth_raw = defaultdict(lambda: {"in": 0, "out": 0})
        self.last_stats = {} # pid -> {"in_kbps": X, "out_kbps": Y}
        self.last_calc_time = time.time()
        
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

    def update_flow_map(self, flow_map):
        """Standardizes the flow map for cross-referencing."""
        self.flow_map = flow_map

    def _process_packet(self, pkt):
        """Entry point for every captured packet."""
        if not pkt.haslayer(IP):
            return

        # 0. Bandwidth Accounting
        payload_len = len(pkt)
        src_flow = (pkt[IP].src, pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else None))
        dst_flow = (pkt[IP].dst, pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else None))
        
        # Attribute to PID
        pid = self.flow_map.get(src_flow) or self.flow_map.get(dst_flow)
        if pid:
            if self.flow_map.get(src_flow) == pid:
                self.bandwidth_raw[pid]["out"] += payload_len
            else:
                self.bandwidth_raw[pid]["in"] += payload_len

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

    def get_bandwidth_report(self):
        """Calculates KB/s per process since the last call and resets raw counters."""
        now = time.time()
        delta = now - self.last_calc_time
        if delta <= 0: return self.last_stats
        
        report = {}
        for pid, counters in self.bandwidth_raw.items():
            report[pid] = {
                "in_kbps": round((counters["in"] / 1024) / delta, 2),
                "out_kbps": round((counters["out"] / 1024) / delta, 2)
            }
        
        # Reset raw counters for next interval
        self.bandwidth_raw.clear()
        self.last_calc_time = now
        self.last_stats = report
        return report
