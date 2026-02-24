import threading
import time
from collections import deque, defaultdict

# Try to import scapy — requires Npcap on Windows
try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
    SCAPY_AVAILABLE = True
except Exception as e:
    # Proper logging of import failure for security visibility
    # console.print is not available here, so we use a standard print
    print(f"[DPI] Scapy import failed: {e}. Some features will be limited.")
    SCAPY_AVAILABLE = False

try:
    from kharma.ebpf_spy import EBPSpy
except ImportError:
    try:
        from ebpf_spy import EBPSpy
    except ImportError:
        EBPSpy = None

try:
    from kharma.fingerprint import FingerprintEngine
    from kharma.yara_scanner import YaraScanner
except ImportError:
    try:
        from fingerprint import FingerprintEngine
        from yara_scanner import YaraScanner
    except ImportError:
        FingerprintEngine = None
        YaraScanner = None

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
        self.recent_payloads = {} # pid -> last raw payload (bytes)
        self.last_stats = {} # pid -> {"in_kbps": X, "out_kbps": Y}
        self.last_calc_time = time.time()
        
        # Sentinel: eBPF Integration
        self.ebpf = EBPSpy() if EBPSpy else None
        self.last_ebpf_stats = {} # pid -> last_total_bytes
        
        # Sentinel: Phase 2 Engines
        self.fingerprint = FingerprintEngine() if FingerprintEngine else None
        self.yara = YaraScanner() if YaraScanner else None

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
            print(f"[DPI] Sniffer loop error: {e}")
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
            
            # Sentinel: Store a sample of the raw payload for Entropy analysis
            if pkt.haslayer(Raw):
                self.recent_payloads[pid] = pkt[Raw].load[:1024] # Store first 1KB

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
            except Exception: # nosec
                # Silent pass is intentional for payload decoding failures
                pass

            # JA3 Fingerprinting (TLS Handshake)
            if self.fingerprint:
                ja3 = self.fingerprint.extract_ja3(payload)
                if ja3:
                    software = self.fingerprint.get_software_name(ja3)
                    summary["info"] = f"Client: {software} (JA3:{ja3[:8]})"
                    summary["ja3"] = ja3

            # YARA Scanning (MALWARE Signature Match)
            if self.yara and self.yara.available:
                matches = self.yara.scan(payload)
                if matches:
                    summary["severity"] = "danger"
                    summary["alert"] = f"YARA: {', '.join(matches)}"

            # Signature Matching (Legacy)
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

    def get_recent_payloads(self):
        """Returns the captured payload samples and clears the buffer."""
        tmp = self.recent_payloads.copy()
        self.recent_payloads.clear()
        return tmp

    def get_bandwidth_report(self):
        """Calculates KB/s per process since last call. Merges kernel eBPF data if available."""
        now = time.time()
        delta = now - self.last_calc_time
        if delta <= 0: return self.last_stats
        
        report = {}
        # 1. Start with raw Scapy/DPI stats
        for pid, counters in self.bandwidth_raw.items():
            report[pid] = {
                "in_kbps": round((counters["in"] / 1024) / delta, 2),
                "out_kbps": round((counters["out"] / 1024) / delta, 2)
            }
        
        # 2. Augment/Correct with eBPF Kernel data (Linux only)
        if self.ebpf and self.ebpf.enabled:
            current_ebpf = self.ebpf.get_stats()
            for pid, total_bytes in current_ebpf.items():
                last_total = self.last_ebpf_stats.get(pid, total_bytes)
                diff = max(0, total_bytes - last_total)
                
                # eBPF currently tracks outbound (tcp_sendmsg)
                ebpf_kbps = round((diff / 1024) / delta, 2)
                
                if pid in report:
                    # Prefer eBPF as it's more accurate/performant, but keep Scapy if eBPF is 0
                    if ebpf_kbps > 0:
                        report[pid]["out_kbps"] = ebpf_kbps
                else:
                    report[pid] = {"in_kbps": 0, "out_kbps": ebpf_kbps}
            
            self.last_ebpf_stats = current_ebpf

        # Reset raw counters for next interval
        self.bandwidth_raw.clear()
        self.last_calc_time = now
        self.last_stats = report
        return report
