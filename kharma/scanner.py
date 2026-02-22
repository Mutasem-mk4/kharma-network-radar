import psutil
from collections import defaultdict

class NetworkScanner:
    def __init__(self):
        self.connections = []
        self.process_names = {}
        self.flow_map = {} # Maps (local_ip, local_port) -> PID
        
    def scan(self):
        """Scans the system for active network connections and their associated processes."""
        self.connections = psutil.net_connections(kind='inet')
        self._update_process_mapping()
        self._update_flow_map()

    def _update_flow_map(self):
        """Builds a map of local socket addresses to PIDs."""
        self.flow_map.clear()
        for conn in self.connections:
            if conn.laddr:
                self.flow_map[(conn.laddr.ip, conn.laddr.port)] = conn.pid

    def _update_process_mapping(self):
        """Build a cache of PID to Process Name for faster lookup, handling access denied errors."""
        self.process_names.clear()
        self.process_exe = {}
        for p in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                self.process_names[p.info['pid']] = p.info['name']
                self.process_exe[p.info['pid']] = p.info['exe']
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                self.process_names[p.info['pid']] = "Unknown/Access Denied"
                self.process_exe[p.info['pid']] = None

    def get_active_connections(self):
        """
        Returns a structured list of active, established external connections.
        Filters out internal loopback/listening sockets for a cleaner view.
        """
        active_conns = []
        for conn in self.connections:
            if conn.status == 'ESTABLISHED':
                # Skip localhost/loopback connections to focus on external traffic
                if conn.raddr and conn.raddr.ip not in ('127.0.0.1', '::1', '0.0.0.0'):
                    p_name = self.process_names.get(conn.pid, str(conn.pid) if conn.pid else "System")
                    p_exe = self.process_exe.get(conn.pid, None)
                    
                    active_conns.append({
                        'pid': conn.pid,
                        'name': p_name,
                        'exe': p_exe,
                        'local_ip': conn.laddr.ip,
                        'local_port': conn.laddr.port,
                        'remote_ip': conn.raddr.ip,
                        'remote_port': conn.raddr.port,
                        'status': conn.status
                    })
        
        # Sort by Process Name, then Remote IP
        return sorted(active_conns, key=lambda x: (x['name'], x['remote_ip']))

