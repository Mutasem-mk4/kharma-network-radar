import click
from rich.console import Console
from rich.live import Live
import time
import platform
import os
import sys

# Internal Modules
try:
    from kharma.scanner import NetworkScanner
    from kharma.dashboard import create_radar_table
    from kharma.geoip import GeoIPResolver
    from kharma.threat import ThreatIntelligence
    from kharma.logger import TrafficLogger
    from kharma.sniffer import DPISniffer
except ImportError:
    # Fallback for local execution or PyInstaller
    from scanner import NetworkScanner
    from dashboard import create_radar_table
    from geoip import GeoIPResolver
    from threat import ThreatIntelligence
    from logger import TrafficLogger
    from sniffer import DPISniffer


console = Console()

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """
    kharma - The Over-Watch Network Monitor.
    Reveals hidden connections and bad karma processes.
    """
    if ctx.invoked_subcommand is None:
        run_radar()

@cli.command('run')
@click.option('--log', is_flag=True, help="Silently log new connections to a local history database.")
@click.option('--filter', '-f', default=None, help="Only show processes that match this name (e.g. 'chrome').")
@click.option('--malware-only', '-m', is_flag=True, help="Only display connections flagged as known malware/botnets.")
@click.option('--protect', '-p', is_flag=True, help="Auto-Kill mode: Instantly terminate any process connecting to a malware IP.")
def run_cmd(log, filter, malware_only, protect):
    """Start the Live Network Radar."""
    run_radar(log_enabled=log, proc_filter=filter, malware_only=malware_only, auto_kill=protect)

@cli.command('history')
@click.option('--limit', default=50, help="Number of past connections to show.")
@click.option('--malware-only', is_flag=True, help="Only show historical connections flagged as Malware.")
def history_cmd(limit, malware_only):
    """View the Time Machine history of past network connections."""
    logger = TrafficLogger()
    logger.show_history(limit=limit, only_malware=malware_only)

def run_radar(log_enabled=False, proc_filter=None, malware_only=False, auto_kill=False):
    # Ensure run as admin/root for full visibility
    if platform.system() == "Windows":
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            console.print("[yellow]Requesting Administrator privileges to view all processes...[/yellow]")
            time.sleep(1)
            # Re-run the program with admin rights
            # sys.executable is the Python interpreter OR the PyInstaller .exe
            # sys.argv contains the script and arguments
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
            
            # Windows UAC Elevation Logic
            # We explicitly invoke the Python interpreter natively to avoid exe wrapper issues
            if getattr(sys, 'frozen', False):
                # When packaged as a PyInstaller executable
                exe_path = sys.executable
                cmd_args = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
                ctypes.windll.shell32.ShellExecuteW(None, "runas", exe_path, cmd_args, None, 1)
            else:
                # When running as a pip-installed script or raw python script
                python_exe = sys.executable
                # Extract arguments passed to the script
                args = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
                module_call = f'-m kharma.main {args}'
                
                # Execute python explicitly as Admin
                ctypes.windll.shell32.ShellExecuteW(None, "runas", python_exe, module_call, None, 1)
                
            # Exit this unprivileged instance
            sys.exit(0)
    else:
        if os.geteuid() != 0:
            console.print("[yellow]Warning: Kharma is running without Root privileges. Many connections will be hidden. Try 'sudo kharma'.[/yellow]")
            time.sleep(2)

    try:
        console.print("[cyan]Initializing Kharma Radar...[/cyan]")
        console.print("[dim]Checking Intel Databases...[/dim]")
        scanner = NetworkScanner()
        geoip = GeoIPResolver()
        intel = ThreatIntelligence()
        logger = TrafficLogger() if log_enabled else None
        
        if log_enabled:
            console.print("[dim]Traffic Logging ENABLED. Writing to history database.[/dim]")
        if proc_filter:
            console.print(f"[dim]Filtering for process: '{proc_filter}'[/dim]")
        if malware_only:
            console.print("[bold red]MALWARE-ONLY MODE ENABLED. Hide all safe traffic.[/bold red]")
        if auto_kill:
            console.print("[bold white on red blink] 🛡️  AUTO-KILL IPS ENABLED. Malware connections will be terminated instantly. [/bold white on red blink]")
        
        with Live(create_radar_table(scanner, geoip, intel, logger, proc_filter, malware_only, auto_kill), console=console, refresh_per_second=2) as live:
            try:
                while True:
                    live.update(create_radar_table(scanner, geoip, intel, logger, proc_filter, malware_only, auto_kill))
                    time.sleep(1.5)
            except KeyboardInterrupt:
                console.print("\n[dim]Radar offline. Stay safe.[/dim]")
                sys.exit(0)
    except Exception as e:
        import traceback
        with open(os.path.expanduser("~/.kharma/crash.log"), "w") as f:
            f.write(traceback.format_exc())
        console.print(f"[bold red]CRASHED: {e}[/bold red]")
        time.sleep(10) # Keep window open to read error
        sys.exit(1)

@cli.command()
@click.argument('pid', type=int)
def kill(pid):
    """Purge a process by its PID to balance system karma."""
    import psutil
    try:
        p = psutil.Process(pid)
        pname = p.name()
        if click.confirm(f"Are you sure you want to terminate '{pname}' (PID: {pid})?", abort=True):
            p.terminate()
            p.wait(timeout=3)
            console.print(f"[green]Process '{pname}' (PID: {pid}) has been terminated.[/green]")
    except psutil.NoSuchProcess:
        console.print(f"[red]Error: Process with PID {pid} not found.[/red]")
    except psutil.AccessDenied:
        console.print(f"[red]Error: Access denied. You may need higher privileges (Root/Admin) to kill PID {pid}.[/red]")
    except Exception as e:
        console.print(f"[red]Unexpected error terminating process: {e}[/red]")

@cli.command('sniff')
@click.argument('pid', type=int)
@click.option('--count', default=100, help="Maximum number of packets to capture.")
def sniff_cmd(pid, count):
    """Deep Packet Inspection (DPI). Sniff live traffic from a specific PID."""
    sniffer = DPISniffer(pid)
    sniffer.start_sniffing(packet_count=count)

@cli.command('_daemon_run', hidden=True)
@click.option('--protect', is_flag=True)
def daemon_run(protect):
    try:
        from kharma.daemon import KharmaDaemon
    except ImportError:
        from daemon import KharmaDaemon
    try:
        daemon = KharmaDaemon(auto_kill=protect)
        daemon.run()
    except Exception as e:
        pass # Die silently in background

@cli.group()
def daemon():
    """Manage silent background monitoring and alerts."""
    pass

@daemon.command('start')
@click.option('--protect', '-p', is_flag=True, help="Enable Auto-Kill while in background.")
def daemon_start(protect):
    """Start the background daemon."""
    console.print("[cyan]Spawning Kharma Background Daemon...[/cyan]")
    import subprocess
    import sys
    script = os.path.abspath(sys.argv[0])
    args = [sys.executable, script, "_daemon_run"]
    if protect:
        args.append("--protect")
        
    if getattr(sys, 'frozen', False):
        args = [sys.executable, "_daemon_run"]
        if protect:
             args.append("--protect")
             
    try:
        if platform.system() == "Windows":
            subprocess.Popen(args, creationflags=0x00000008) # DETACHED_PROCESS
        else:
            subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        console.print("[bold green]Daemon deployed successfully. Monitoring network in the background.[/bold green]")
        if protect:
            console.print("[bold red]Active Defense (Auto-Kill) is ENABLED.[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Failed to start daemon: {e}[/bold red]")

@daemon.command('config')
@click.option('--bot-token', prompt=True, hide_input=True, help="Telegram Bot Token")
@click.option('--chat-id', prompt=True, help="Telegram Chat ID")
def daemon_config(bot_token, chat_id):
    """Configure Telegram Alerts."""
    import json
    config_path = os.path.expanduser("~/.kharma/daemon_config.json")
    with open(config_path, "w") as f:
        json.dump({"telegram_bot_token": bot_token, "telegram_chat_id": chat_id}, f)
    console.print(f"[green]Configuration saved to {config_path}[/green]")
    console.print("[cyan]Telegram alerts are now active for the daemon.[/cyan]")

if __name__ == '__main__':
    cli()
