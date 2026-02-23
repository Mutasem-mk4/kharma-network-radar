import sqlite3
import os
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

class TrafficLogger:
    """
    Quietly logs newly discovered external connections to a local SQLite database.
    Allows for historical review of network activity (The Time Machine feature).
    """
    def __init__(self):
        # Store DB in a persistent user directory so it survives PyInstaller unpacks
        self.config_dir = os.path.expanduser('~/.kharma')
        os.makedirs(self.config_dir, exist_ok=True)
        self.db_path = os.path.join(self.config_dir, 'kharma_history.db')
        self._init_db()
        self.seen_connections = set() # To avoid logging the exact same active connection every second

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    process_name TEXT,
                    pid INTEGER,
                    remote_ip TEXT,
                    remote_port INTEGER,
                    location TEXT,
                    is_malware BOOLEAN
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            console.print(f"[dim red]Logger init failed: {e}[/dim red]")

    def log_connection(self, process_name, pid, remote_ip, remote_port, location, is_malware):
        """Logs a connection if we haven't seen this exact combo recently."""
        # Create a unique signature for this connection
        conn_sig = f"{pid}-{remote_ip}:{remote_port}"
        
        if conn_sig not in self.seen_connections:
            self.seen_connections.add(conn_sig)
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO connections (timestamp, process_name, pid, remote_ip, remote_port, location, is_malware)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (datetime.now(), process_name, pid, remote_ip, remote_port, location, is_malware))
                conn.commit()
                conn.close()
            except Exception as e:
                console.print(f"[dim red]Logger write failed: {e}[/dim red]")

    def show_history(self, limit=50, only_malware=False):
        """Prints a rich table of historical connections."""
        if not os.path.exists(self.db_path):
            console.print("[yellow]No history database found. Make sure to run 'kharma --log' to start recording.[/yellow]")
            return

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = "SELECT timestamp, process_name, pid, remote_ip, remote_port, location, is_malware FROM connections"
            if only_malware:
                query += " WHERE is_malware = 1"
            query += f" ORDER BY timestamp DESC LIMIT {limit}"
            
            cursor.execute(query)
            rows = cursor.fetchall()
            conn.close()

            if not rows:
                console.print("[dim]No historical connections found matching the criteria.[/dim]")
                return

            table = Table(
                title=f"[bold cyan]⏳ Kharma Time Machine (Last {len(rows)} connections)[/bold cyan]",
                show_header=True, 
                header_style="bold magenta",
                box=box.MINIMAL_DOUBLE_HEAD
            )
            
            table.add_column("Time", style="dim", width=19)
            table.add_column("Process Name", style="cyan")
            table.add_column("PID", style="dim", justify="right")
            table.add_column("Remote IP:Port")
            table.add_column("Location", style="blue")
            
            for row in reversed(rows): # Print oldest first from the limited set to read naturally top-down
                ts_str = row[0][:19] # Cut off microseconds
                p_name = row[1]
                pid = str(row[2])
                remote = f"{row[3]}:{row[4]}"
                location = row[5]
                is_malware = row[6]
                
                if is_malware:
                    p_name = f"[bold red blink]🚨 {p_name}[/bold red blink]"
                    remote = f"[bold white on red blink] {remote} [/bold white on red blink]"
                    location = f"[bold red]{location}[/bold red]"
                else:
                    remote = f"[yellow]{remote}[/yellow]"
                    
                table.add_row(ts_str, p_name, pid, remote, location)
                
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error reading history: {e}[/red]")
