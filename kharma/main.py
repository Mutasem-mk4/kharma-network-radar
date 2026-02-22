import rich_click as click
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
    from kharma.vt_engine import VTEngine
except ImportError:
    # Fallback for local execution or PyInstaller
    from scanner import NetworkScanner
    from dashboard import create_radar_table
    from geoip import GeoIPResolver
    from threat import ThreatIntelligence
    from logger import TrafficLogger
    from sniffer import DPISniffer
    from vt_engine import VTEngine


console = Console()

click.rich_click.USE_RICH_MARKUP = True
click.rich_click.SHOW_ARGUMENTS = True
click.rich_click.GROUP_ARGUMENTS_OPTIONS = True
click.rich_click.STYLE_ERRORS_SUGGESTION = "magenta italic"
click.rich_click.ERRORS_SUGGESTION = "Try running '--help' for a list of available commands."
click.rich_click.ERRORS_EPILOGUE = "To find out more, visit [link=https://github.com/mutasem-mk4]github.com/mutasem-mk4[/link]"

# Customize the display of the main group commands
click.rich_click.COMMAND_GROUPS = {
    "kharma": [
        {
            "name": "📡 Intelligence Ops",
            "commands": ["run", "web", "history", "sniff"],
        },
        {
            "name": "🛡️ Active Defense",
            "commands": ["kill"],
        },
        {
            "name": "⚙️ System & Config",
            "commands": ["daemon", "config"],
        },
    ]
}

click.rich_click.OPTION_GROUPS = {
    "kharma run": [
        {
            "name": "Visualization Options",
            "options": ["--filter", "--malware-only"],
        },
        {
            "name": "Operational Controls",
            "options": ["--log", "--protect"],
        },
    ]
}

HEADER = r"""
[bold cyan]
 _  _
|_/ 
| \ [/bold cyan] [bold white]KHARMA[/bold white]
[dim]Live Network Radar[/dim]
"""

@click.group(invoke_without_command=True, epilog=f"""
{HEADER}
[bold underline]🚀 Quick Start[/bold underline]
[cyan]• Radar:[/cyan] [white]kharma run[/white]
[cyan]• Web:[/cyan]   [white]kharma web[/white]
[cyan]• Shield:[/cyan][white]kharma run --protect[/white]
[cyan]• Silent:[/cyan][white]kharma daemon start[/white]

[dim italic]Run 'kharma [CMD] --help'[/dim italic]
""")
@click.pass_context
def cli(ctx):
    """
    [bold cyan]Kharma - The Over-Watch Network Monitor[/bold cyan]
    
    Reveals hidden connections and bad karma processes on your system.
    Built for active defense, forensics, and zero-latency geolocation.
    """
    if ctx.invoked_subcommand is None:
        run_radar()

@cli.command('run', epilog="""
[bold underline]Tactical Examples:[/bold underline]

  [cyan]Standard Radar:[/cyan]        [white]kharma run[/white]
  [cyan]Focus Browser:[/cyan]         [white]kharma run --filter chrome[/white]
  [cyan]Threat Hunting:[/cyan]        [white]kharma run --malware-only[/white]
  [cyan]Interceptor Mode:[/cyan]      [white]kharma run --log --protect[/white]

[dim yellow]PRO TIP: Use '--protect' to automatically terminate malware threads before they exfiltrate data.[/dim yellow]
""")
@click.option('--log', is_flag=True, help="[dim]Database:[/dim] Silently log new connections to the local forensics history.")
@click.option('--filter', '-f', default=None, help="[dim]Attribute:[/dim] Only show processes matching this name (case-insensitive).")
@click.option('--malware-only', '-m', is_flag=True, help="[dim]Intelligence:[/dim] Stealth mode - hide all safe traffic, highlight only C2/Botnets.")
@click.option('--protect', '-p', is_flag=True, help="[bold red]SHIELD:[/bold red] Instantly terminate any process connecting to a malicious IP.")
def run_cmd(log, filter, malware_only, protect):
    """[📡] Launch the Live Intelligence Radar UI."""
    run_radar(log_enabled=log, proc_filter=filter, malware_only=malware_only, auto_kill=protect)

@cli.command('history', epilog="""
[bold underline]Forensics Examples:[/bold underline]

  [cyan]Recent History:[/cyan]      [white]kharma history[/white]
  [cyan]Deep Search:[/cyan]         [white]kharma history --limit 500[/white]
  [cyan]Malware Replay:[/cyan]      [white]kharma history --malware-only[/white]

[dim italic]Historical data is stored locally in ~/.kharma/forensics.db[/dim italic]
""")
@click.option('--limit', default=50, help="Number of historical events to retrieve.")
@click.option('--malware-only', is_flag=True, help="Filter history to only show confirmed threat detections.")
def history_cmd(limit, malware_only):
    """[📜] View the Time Machine history of past network connections."""
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
        vt_engine = VTEngine()
        logger = TrafficLogger() if log_enabled else None
        
        if log_enabled:
            console.print("[dim]Traffic Logging ENABLED. Writing to history database.[/dim]")
        if proc_filter:
            console.print(f"[dim]Filtering for process: '{proc_filter}'[/dim]")
        if malware_only:
            console.print("[bold red]MALWARE-ONLY MODE ENABLED. Hide all safe traffic.[/bold red]")
        if auto_kill:
            console.print("[bold white on red blink] 🛡️  AUTO-KILL IPS ENABLED. Malware connections will be terminated instantly. [/bold white on red blink]")
        if vt_engine.api_key:
            console.print("[bold green]🧬 VirusTotal Engine is ONLINE. Deep Process Hashing active.[/bold green]")
        else:
            console.print("[yellow]⚠️  VirusTotal Engine is offline. Run 'kharma config vt <API_KEY>' to enable deep EDR scanning.[/yellow]")
        
        with Live(create_radar_table(scanner, geoip, intel, vt_engine, logger, proc_filter, malware_only, auto_kill), console=console, refresh_per_second=2) as live:
            try:
                while True:
                    live.update(create_radar_table(scanner, geoip, intel, vt_engine, logger, proc_filter, malware_only, auto_kill))
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

@cli.command('kill', epilog="""
[bold underline]Neutralization:[/bold underline]

  [cyan]Kill PID:[/cyan]           [white]kharma kill 8542[/white]

[bold red]CAUTION:[/bold red] Use this command with care. Terminating essential system processes may cause instability.
""")
@click.argument('pid', type=int)
def kill(pid):
    """[🔪] Purge a malicious process by its PID to restore system karma."""
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

@cli.command('sniff', epilog="""
[bold underline]Cyber-Ops Examples:[/bold underline]

  [cyan]Standard Sniff:[/cyan]        [white]kharma sniff 8542[/white]
  [cyan]Deep Capture:[/cyan]          [white]kharma sniff 8542 --count 1000[/white]

[bold yellow]Requirement:[/bold yellow] DPI sniffing requires [white]Npcap[/white] (Windows) or [white]Root[/white] (Linux).
""")
@click.argument('pid', type=int)
@click.option('--count', default=100, help="Total packet limit for this capture session.")
def sniff_cmd(pid, count):
    """[🕵️] Deep Packet Inspection. Sniff live payloads from a specific PID."""
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

@cli.group('daemon', epilog="""
[bold underline]Tactical Background Monitoring:[/bold underline]
Launches an invisible Kharma instance that monitors the network 
autonomously and sends real-time alerts via:
  - [bold yellow]Desktop Notifications[/bold yellow] (Cross-platform)
  - [bold cyan]Telegram Bot Hooks[/bold cyan] (Global)

[dim italic]Configure alerts first using 'kharma daemon config'[/dim italic]
""")
def daemon():
    """[👻] Manage silent background monitoring and alerts."""
    pass

@daemon.command('start', epilog="""
    [bold underline]Examples:[/bold underline]
    [cyan]kharma daemon start[/cyan]               Start silent monitoring. 
    [cyan]kharma daemon start --protect[/cyan]     Start silent monitoring + [bold red]Auto-Kill Malware[/bold red].
""")
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
    config = {}
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            try:
                config = json.load(f)
            except:
                pass
    config["telegram_bot_token"] = bot_token
    config["telegram_chat_id"] = chat_id
    
    with open(config_path, "w") as f:
        json.dump(config, f)
    console.print(f"[green]Configuration saved to {config_path}[/green]")
    console.print("[cyan]Telegram alerts are now active for the daemon.[/cyan]")

@cli.group('config', epilog="""
    [bold underline]Description:[/bold underline]
    Manage global configurations, API keys, and notification integrations 
    for both the Live Radar and the Background Daemon.
""")
def config():
    """Manage global tool configurations and API keys."""
    pass

@config.command('vt', epilog="""
    [bold underline]Examples:[/bold underline]
    [cyan]kharma config vt e3b0c44298fc...[/cyan]    Register your free VirusTotal API key.
""")
@click.argument('api_key')
def config_vt(api_key):
    """Set the VirusTotal API Key for Host-based Deep Malware Scanning."""
    import json
    config_path = os.path.expanduser("~/.kharma/daemon_config.json")
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    
    config_data = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                config_data = json.load(f)
        except Exception:
            pass
            
    config_data['vt_api_key'] = api_key
    with open(config_path, "w") as f:
        json.dump(config_data, f)
        
    console.print(f"[bold green]VirusTotal API Key registered successfully![/bold green]")
    console.print("[cyan]Kharma will now natively hash all external socket connections and verify them against 70+ AV engines in the cloud.[/cyan]")

@cli.command('web', epilog="""
[bold underline]Description:[/bold underline]
Launches a browser-based Command Center with global IP mapping,
live animations, and integrated threat intelligence panels.

  [cyan]Standard Web:[/cyan]          [white]kharma web[/white]
  [cyan]Custom Port:[/cyan]           [white]kharma web --port 9090[/white]

[dim white]Internal URL: http://localhost:8085[/dim white]
""")
@click.option('--port', default=8085, help="Specify a custom port for the intelligence server.")
def web_cmd(port):
    """[🌐] Deploy the Full-Stack Dark Dashboard UI."""
    import threading
    import webbrowser
    
    try:
        from kharma.server import KharmaWebServer
    except ImportError:
        from server import KharmaWebServer
        
    # Ensure run as admin/root for full visibility
    if platform.system() == "Windows":
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            console.print("[yellow]Warning: Running Kharma Web without Administrator privileges. Some processes will be hidden.[/yellow]")
    else:
        if os.geteuid() != 0:
            console.print("[yellow]Warning: Running Kharma Web without Root privileges. Some connections will be hidden.[/yellow]")
            
    server = KharmaWebServer(port=port)
    
    console.print(f"[bold cyan]Initializing Kharma Web Dashboard...[/bold cyan]")
    console.print(f"[dim]Spawning background data scanner loop...[/dim]")
    
    # Delay browser opening slightly so server can bind the port
    def open_browser():
        time.sleep(1.5)
        url = f"http://127.0.0.1:{port}"
        console.print(f"[bold green]Dashboard launched at: {url}[/bold green]")
        console.print(f"[dim](Press CTRL+C in this terminal to shutdown the radar)[/dim]")
        webbrowser.open(url)
        
    threading.Thread(target=open_browser, daemon=True).start()
    
    try:
        server.start()
    except KeyboardInterrupt:
        console.print("\n[dim]Web Radar offline. Stay safe.[/dim]")
    except Exception as e:
        console.print(f"[red]Failed to start internal web server: {e}[/red]")

if __name__ == '__main__':
    cli()
