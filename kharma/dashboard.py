from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich import box
import psutil

def create_radar_table(scanner, geoip_resolver, intel, vt_engine=None, logger=None, proc_filter=None, malware_only=False, auto_kill=False):
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
    table.add_column("VT Score", style="magenta", width=12, justify="center")
    table.add_column("Status", style="bold")

    # Fetch connections and process names
    connections = scanner.get_active_connections()
    
    # Track unique processes for the header summary
    unique_pids = set()
    active_count = 0

    for conn in connections:
        # Since get_active_connections returns a list of dictionaries filtered by ESTABLISHED and External IPs
        p_name = conn['name']
        
        # Apply Process Filter
        if proc_filter and proc_filter.lower() not in p_name.lower():
            continue

        active_count += 1
        pid_str = str(conn['pid']) if conn['pid'] else "-"
        if conn['pid']:
            unique_pids.add(conn['pid'])
            
        # Highlight potentially suspicious names (basic example)
        if p_name.lower() in ['nc', 'ncat', 'python', 'python3', 'bash', 'sh']:
            p_name = f"[bold red blink]{p_name}[/bold red blink]"
        elif p_name == "Unknown":
            p_name = f"[dim]{p_name}[/dim]"
        
        local_port = str(conn['local_port']) if conn['local_port'] else "-"
        
        # Check Threat Intelligence
        is_malware = False
        remote = "-"
        ip = conn['remote_ip']
        port = conn['remote_port']
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
        loc_data = geoip_resolver.resolve(ip)
        location = loc_data[2] if isinstance(loc_data, tuple) and len(loc_data) >= 3 else str(loc_data)
        
        if is_malware:
            location = f"[bold red blink]{location} [MALWARE][/bold red blink]"
        
        # VirusTotal Engine Hash Analysis
        vt_score_display = "[dim]-[/dim]"
        vt_is_malicious = False
        
        if vt_engine and 'exe' in conn and conn['exe']:
            file_hash = vt_engine.get_file_hash(conn['exe'])
            malicious, total = vt_engine.check_hash(file_hash)
            
            if malicious is not None and total is not None:
                if malicious > 0:
                    vt_score_display = f"[bold white on red blink]{malicious}/{total}[/bold white on red blink]"
                    vt_is_malicious = True
                    is_malware = True # Upgrade overall status to malware
                    p_name = f"[bold red blink]🚨 {p_name} 🚨[/bold red blink]"
                else:
                    vt_score_display = f"[green]0/{total}[/green]"
        elif vt_engine and 'exe' in conn and not conn['exe']:
             vt_score_display = "[dim]Denied[/dim]"
        
        # Colorize Status
        status = f"[green]{conn['status']}[/green]"
        if is_malware:
            status = f"[bold red blink]BREACHED[/bold red blink]"
            if auto_kill and conn['pid']:
                try:
                    # Active Defense: Auto-Kill
                    p = psutil.Process(conn['pid'])
                    p_name_lower = p.name().lower()
                    critical_procs = {'system idle process', 'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'explorer.exe', 'winlogon.exe'}
                    if p_name_lower in critical_procs:
                        status = f"[bold yellow blink]OS CRITICAL. SAFE[/bold yellow blink]"
                    else:
                        p.terminate()
                        status = f"[bold white on red blink]AUTO-KILLED[/bold white on red blink]"
                        p_name = f"[strike]{p_name}[/strike]"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    status = f"[bold red blink]KILL FAILED[/bold red blink]"
            
        # Traffic Logging (Time Machine)
        if logger and ip:
            # Strip rich tags for logging
            clean_pname = p_name.replace("[bold red blink]🚨 ", "").replace(" 🚨[/bold red blink]", "")
            clean_loc = location.replace("[bold red blink]", "").replace(" [MALWARE][/bold red blink]", "")
            logger.log_connection(clean_pname, conn['pid'], ip, port, clean_loc, is_malware)
        
        table.add_row(
            p_name,
            pid_str,
            local_port,
            remote,
            location,
            vt_score_display,
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
