from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich import box
import psutil

def create_radar_table(scanner, geoip_resolver, intel, logger=None, proc_filter=None, malware_only=False):
    """
    Creates the main Rich table displaying the live network connections.
    """
    table = Table(
        show_header=True, 
        header_style="bold magenta",
        box=box.MINIMAL_DOUBLE_HEAD,
        expand=True
    )
    
    table.add_column("Process Name", style="cyan", width=20)
    table.add_column("PID", style="dim", width=8, justify="right")
    table.add_column("Local Port", style="green", width=12)
    table.add_column("Remote IP:Port", width=25) # Removed yellow style, will color dynamically
    table.add_column("Location", style="blue")
    table.add_column("Status", style="bold")

    # Fetch connections and process names
    scanner.scan()
    connections = scanner.connections
    
    # Track unique processes for the header summary
    unique_pids = set()
    active_count = 0

    for conn in connections:
        if conn.status == 'ESTABLISHED':
            # Skip loopback for cleaner view, unless it's the only thing happening
            if conn.raddr and conn.raddr.ip not in ('127.0.0.1', '::1', '0.0.0.0'):
                p_name = scanner.process_names.get(conn.pid, "Unknown")
                
                # Apply Process Filter
                if proc_filter and proc_filter.lower() not in p_name.lower():
                    continue

                active_count += 1
                pid_str = str(conn.pid) if conn.pid else "-"
                if conn.pid:
                    unique_pids.add(conn.pid)
                    
                # Highlight potentially suspicious names (basic example)
                if p_name.lower() in ['nc', 'ncat', 'python', 'python3', 'bash', 'sh']:
                    p_name = f"[bold red blink]{p_name}[/bold red blink]"
                elif p_name == "Unknown":
                    p_name = f"[dim]{p_name}[/dim]"
                
                local_port = str(conn.laddr.port) if conn.laddr else "-"
                
                # Check Threat Intelligence
                is_malware = False
                remote = "-"
                ip = conn.raddr.ip
                port = conn.raddr.port
                is_malware = intel.check_ip(ip)
                
                # Apply Malware-Only Filter
                if malware_only and not is_malware:
                    active_count -= 1 # Revert the active count addition
                    continue
                    
                if is_malware:
                    remote = f"[bold white on red blink] {ip}:{port} [/bold white on red blink]"
                    p_name = f"[bold red blink]🚨 {p_name} 🚨[/bold red blink]"
                else:
                    remote = f"[yellow]{ip}:{port}[/yellow]"
                
                # Resolve Location
                location = geoip_resolver.resolve(ip)
                if is_malware:
                    location = f"[bold red blink]{location} [MALWARE][/bold red blink]"
                
                # Colorize Status
                status = f"[green]{conn.status}[/green]"
                if is_malware:
                    status = f"[bold red blink]BREACHED[/bold red blink]"
                    
                # Traffic Logging (Time Machine)
                if logger and conn.raddr:
                    # Strip rich tags for logging
                    clean_pname = p_name.replace("[bold red blink]🚨 ", "").replace(" 🚨[/bold red blink]", "")
                    clean_loc = location.replace("[bold red blink]", "").replace(" [MALWARE][/bold red blink]", "")
                    logger.log_connection(clean_pname, conn.pid, ip, port, clean_loc, is_malware)
                
                table.add_row(
                    p_name,
                    pid_str,
                    local_port,
                    remote,
                    location,
                    status
                )
    if active_count == 0:
        table.add_row("[dim]No active external connections found.[/dim]", "", "", "", "", "")

    # Create a header panel with summary stats
    cpu_percent = psutil.cpu_percent()
    mem_percent = psutil.virtual_memory().percent
    
    summary_text = (
        f"[bold white]Active Connections:[/bold white] [cyan]{active_count}[/cyan] | "
        f"[bold white]Unique Processes:[/bold white] [magenta]{len(unique_pids)}[/magenta] | "
        f"[bold white]CPU:[/bold white] [{'red' if cpu_percent > 80 else 'green'}]{cpu_percent}%[/{'red' if cpu_percent > 80 else 'green'}] | "
        f"[bold white]RAM:[/bold white] [{'red' if mem_percent > 80 else 'green'}]{mem_percent}%[/{'red' if mem_percent > 80 else 'green'}]"
    )
    
    panel = Panel(
        Align.center(table),
        title=f"[bold cyan]👁️ Kharma Network Radar[/bold cyan]",
        subtitle=summary_text,
        border_style="cyan",
    )
    
    return panel
