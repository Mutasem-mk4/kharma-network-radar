import click
from rich.console import Console
from rich.live import Live
import time
import platform
import os
import sys

# Internal Modules
from scanner import NetworkScanner
from dashboard import create_radar_table
from geoip import GeoIPResolver
from threat import ThreatIntelligence
from logger import TrafficLogger


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
def run_cmd(log, filter, malware_only):
    """Start the Live Network Radar."""
    run_radar(log_enabled=log, proc_filter=filter, malware_only=malware_only)

@cli.command('history')
@click.option('--limit', default=50, help="Number of past connections to show.")
@click.option('--malware-only', is_flag=True, help="Only show historical connections flagged as Malware.")
def history_cmd(limit, malware_only):
    """View the Time Machine history of past network connections."""
    logger = TrafficLogger()
    logger.show_history(limit=limit, only_malware=malware_only)

def run_radar(log_enabled=False, proc_filter=None, malware_only=False):
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
            
            # If we are compiled by PyInstaller, sys.executable == script
            if getattr(sys, 'frozen', False):
                # Running as PyInstaller executable
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
            else:
                # Running as Python script
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
            
            # Exit this unprivileged instance
            sys.exit(0)
    else:
        if os.geteuid() != 0:
            console.print("[yellow]Warning: Kharma is running without Root privileges. Many connections will be hidden. Try 'sudo kharma'.[/yellow]")
            time.sleep(2)

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
    
    with Live(create_radar_table(scanner, geoip, intel, logger, proc_filter, malware_only), console=console, refresh_per_second=2) as live:
        try:
            while True:
                live.update(create_radar_table(scanner, geoip, intel, logger, proc_filter, malware_only))
                time.sleep(1.5)
        except KeyboardInterrupt:
            console.print("\n[dim]Radar offline. Stay safe.[/dim]")
            sys.exit(0)

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

if __name__ == '__main__':
    cli()
