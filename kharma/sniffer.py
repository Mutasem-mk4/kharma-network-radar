import os
import sys
from scapy.all import sniff, IP, TCP, UDP, Raw
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
import psutil

console = Console()

class DPISniffer:
    def __init__(self, target_pid):
        self.target_pid = target_pid
        self.target_ports = set()
        self.target_ips = set()
        
    def _get_process_connections(self):
        """Finds all IP:Port combinations currently used by the target PID."""
        try:
            proc = psutil.Process(self.target_pid)
            conns = proc.connections(kind='inet')
            for conn in conns:
                if conn.status == 'ESTABLISHED' or conn.status == 'LISTEN':
                    if conn.laddr:
                        self.target_ports.add(conn.laddr.port)
                        self.target_ips.add(conn.laddr.ip)
                    if conn.raddr:
                        self.target_ports.add(conn.raddr.port)
                        self.target_ips.add(conn.raddr.ip)
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def _build_bpf_filter(self):
        """Constructs a Berkeley Packet Filter (BPF) string based on the process ports."""
        if not self.target_ports:
            return ""
        
        # We filter by ports to keep the capture highly focused
        port_filters = [f"port {p}" for p in self.target_ports]
        return " or ".join(port_filters)

    def _packet_callback(self, packet):
        """Processes each captured packet matching the BPF filter."""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            proto = "UNKNOWN"
            src_port = 0
            dst_port = 0
            
            if TCP in packet:
                proto = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                proto = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                
            # Check if this packet actually belongs to our target process
            if src_port in self.target_ports or dst_port in self.target_ports:
                
                # Check for raw payload data (Deep Packet Inspection)
                payload_data = ""
                if Raw in packet:
                    try:
                        # Try to decode as UTF-8 (HTTP, cleartext)
                        payload_data = packet[Raw].load.decode('utf-8', errors='ignore').strip()
                    except:
                        payload_data = f"<Binary Data: {len(packet[Raw].load)} bytes>"
                
                # Render to screen
                header = Text(f"[{proto}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}", style="bold cyan")
                
                if payload_data:
                    # Highlight common clear-text protocols
                    if "HTTP" in payload_data or "GET " in payload_data or "POST " in payload_data:
                        content = Text(payload_data[:500] + ("..." if len(payload_data) > 500 else ""), style="green")
                        panel_style = "bold green"
                    else:
                        content = Text(payload_data[:200] + ("..." if len(payload_data) > 200 else ""), style="dim white")
                        panel_style = "dim blue"
                        
                    console.print(Panel(content, title=header, border_style=panel_style, expand=False))
                else:
                    # Just print the connection header if no payload
                    console.print(header)


    def start_sniffing(self, packet_count=100):
        """Initiates the packet capture session."""
        console.print(f"[bold yellow]Initializing Deep Packet Inspection on PID: {self.target_pid}[/bold yellow]")
        
        if not self._get_process_connections():
            console.print(f"[bold red]Error: Could not access PID {self.target_pid}. Either it does not exist or you need Administrator/Root privileges.[/bold red]")
            return

        bpf_filter = self._build_bpf_filter()
        
        if not bpf_filter:
            console.print(f"[bold yellow]Warning: Process {self.target_pid} currently has no active network connections to sniff.[/bold yellow]")
            return
            
        console.print(f"[bold green]Target Ports Identified: {self.target_ports}[/bold green]")
        console.print(f"[dim]Applying BPF Filter: {bpf_filter}[/dim]")
        console.print(f"[bold cyan]Starting capture (Max {packet_count} packets). Press Ctrl+C to stop...[/bold cyan]\n")
        
        try:
            # Requires Npcap on Windows, libpcap on Linux
            sniff(filter=bpf_filter, prn=self._packet_callback, store=0, count=packet_count)
            console.print("\n[bold green]Capture completed successfully.[/bold green]")
        except PermissionError:
             console.print("[bold red]Fatal Error: You MUST run this command as Administrator/Root to capture raw network packets.[/bold red]")
        except RuntimeError as e:
             if "Npcap" in str(e) or "winpcap" in str(e).lower() or "sniff" in str(e).lower():
                 console.print("\n[bold red]Fatal Driver Error:[/bold red] Npcap/WinPcap is not installed on this system.")
                 console.print("Please download and install Npcap from [blue underline]https://npcap.com/[/blue underline] to enable Deep Packet Inspection on Windows.")
             else:
                 console.print(f"[bold red]Capture Error: {e}[/bold red]")
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Capture manually aborted by user.[/bold yellow]")
