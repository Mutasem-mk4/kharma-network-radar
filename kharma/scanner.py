import psutil
from collections import defaultdict

class NetworkScanner:
    def __init__(self):
        self.connections = []
        self.process_names = {}
        
    def scan(self):
        """Scans the system for active network connections and their associated processes."""
        self.connections = psutil.net_connections(kind='inet')
        self._update_process_mapping()

    def _update_process_mapping(self):
        """Build a cache of PID to Process Name for faster lookup, handling access denied errors."""
        self.process_names.clear()
        for p in psutil.process_iter(['pid', 'name']):
            try:
                self.process_names[p.info['pid']] = p.info['name']
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                self.process_names[p.info['pid']] = "Unknown/Access Denied"

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
                    
                    active_conns.append({
                        'pid': conn.pid,
                        'name': p_name,
                        'local_ip': conn.laddr.ip,
                        'local_port': conn.laddr.port,
                        'remote_ip': conn.raddr.ip,
                        'remote_port': conn.raddr.port,
                        'status': conn.status
                    })
        
        # Sort by Process Name, then Remote IP
        return sorted(active_conns, key=lambda x: (x['name'], x['remote_ip']))

