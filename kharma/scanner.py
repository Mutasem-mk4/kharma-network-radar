import psutil
import threading
import time
from collections import defaultdict

class NetworkScanner:
    def __init__(self):
        self.connections_buffer = []
        self.process_names = {}
        self.process_exe = {}
        self.flow_map = {} # Maps (local_ip, local_port) -> PID
        self.io_stats = {} # pid -> io_counters
        self._lock = threading.Lock()
        self.is_running = False
        
    def start_background_scan(self, interval=0.5):
        """Starts a background thread to scan connections continuously."""
        if not self.is_running:
            self.is_running = True
            self.thread = threading.Thread(target=self._scanner_loop, args=(interval,), daemon=True)
            self.thread.start()

    def _scanner_loop(self, interval):
        """Daemon loop for periodic system scanning."""
        while self.is_running:
            try:
                # 1. Capture raw connections
                raw_conns = psutil.net_connections(kind='inet')
                
                # 2. Update process mapping (Optimized: only for new PIDs)
                current_pids = {conn.pid for conn in raw_conns if conn.pid}
                for pid in current_pids:
                    try:
                        # Update cache if missing
                        if pid not in self.process_names:
                            p = psutil.Process(pid)
                            self.process_names[pid] = p.name()
                            self.process_exe[pid] = p.exe()
                        
                        # Always update IO stats for active processes
                        p = psutil.Process(pid)
                        self.io_stats[pid] = p.io_counters()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        if pid not in self.process_names:
                            self.process_names[pid] = "Unknown/Access Denied"
                            self.process_exe[pid] = None
                        self.io_stats[pid] = None

                # 3. Build thread-safe buffer
                processed_conns = []
                new_flow_map = {}
                
                # We include ESTABLISHED for live radar, but also LISTEN and others for "Sentinel Visibility"
                important_states = ('ESTABLISHED', 'LISTEN', 'CLOSE_WAIT', 'FIN_WAIT1', 'FIN_WAIT2')
                
                for conn in raw_conns:
                    # Capture connections that are established OR listening (to show local services)
                    if conn.status in important_states and conn.laddr:
                        p_name = self.process_names.get(conn.pid, str(conn.pid) if conn.pid else "System")
                        p_exe = self.process_exe.get(conn.pid, None)
                        
                        remote_ip = conn.raddr.ip if conn.raddr else "0.0.0.0"
                        remote_port = conn.raddr.port if conn.raddr else 0
                        # Include meaningful local traffic if it's a listener or localhost so UI isn't empty.
                        is_local = remote_ip in ('127.0.0.1', '::1', '0.0.0.0')
                        
                        processed_conns.append({
                            'pid': conn.pid,
                            'name': p_name,
                            'exe': p_exe,
                            'local_ip': conn.laddr.ip,
                            'local_port': conn.laddr.port,
                            'remote_ip': remote_ip,
                            'remote_port': remote_port,
                            'status': conn.status,
                            'io_counters': self.io_stats.get(conn.pid)
                        })
                        new_flow_map[(conn.laddr.ip, conn.laddr.port)] = conn.pid

                with self._lock:
                    # Sort: Established first, then Listeners
                    self.connections_buffer = sorted(
                        processed_conns, 
                        key=lambda x: (0 if x['status'] == 'ESTABLISHED' else 1, x.get('name', ''))
                    )
                    self.flow_map = new_flow_map

            except Exception as e:
                print(f"[SCANNER] Background scan error: {e}")
            
            time.sleep(interval)

    def scan(self):
        """Synchronous scan for cases where a background loop isn't desired."""
        # This is just a wrapper around the logic in _scanner_loop but without the sleep
        try:
            raw_conns = psutil.net_connections(kind='inet')
            current_pids = {conn.pid for conn in raw_conns if conn.pid}
            for pid in current_pids:
                try:
                    if pid not in self.process_names:
                        p = psutil.Process(pid)
                        self.process_names[pid] = p.name()
                        self.process_exe[pid] = p.exe()
                    p = psutil.Process(pid)
                    self.io_stats[pid] = p.io_counters()
                except:
                    if pid not in self.process_names:
                        self.process_names[pid] = "Unknown"
                        self.process_exe[pid] = None
                    self.io_stats[pid] = None

            processed_conns = []
            important_states = ('ESTABLISHED', 'LISTEN', 'CLOSE_WAIT', 'FIN_WAIT1', 'FIN_WAIT2')
            for conn in raw_conns:
                if conn.status in important_states and conn.laddr:
                    p_name = self.process_names.get(conn.pid, str(conn.pid) if conn.pid else "System")
                    p_exe = self.process_exe.get(conn.pid, None)
                    remote_ip = conn.raddr.ip if conn.raddr else "0.0.0.0"
                    remote_port = conn.raddr.port if conn.raddr else 0
                    
                    processed_conns.append({
                        'pid': conn.pid, 'name': p_name, 'exe': p_exe,
                        'local_ip': conn.laddr.ip, 'local_port': conn.laddr.port,
                        'remote_ip': remote_ip, 'remote_port': remote_port,
                        'status': conn.status, 'io_counters': self.io_stats.get(conn.pid)
                    })
            with self._lock:
                self.connections_buffer = processed_conns
        except Exception as e:
            print(f"[SCANNER] Sync scan error: {e}")

    def get_active_connections(self):
        """Returns the latest non-blocking buffered connections."""
        with self._lock:
            return self.connections_buffer.copy()

    def get_flow_map(self):
        """Returns the latest buffered flow map."""
        with self._lock:
            return self.flow_map.copy()
