import requests
import threading
import time
import hmac
import hashlib
import json

class SwarmEngine:
    """
    Kharma Swarm — Multi-Node Hive Architecture.
    Connects multiple machines running Kharma into a single pane of glass.
    """
    def __init__(self, secret_token):
        self.secret_token = secret_token
        self.nodes = [] # List of { 'url': '...', 'token': '...', 'status': '...', 'name': '...' }
        self.hive_data = {} # Latest data from all nodes

    def add_node(self, url, token, name=None):
        """Adds a new remote node to the swarm."""
        if not url.startswith('http'):
            url = f"http://{url}"
        node = {
            "url": url.rstrip('/'),
            "token": token,
            "name": name or f"Node-{len(self.nodes)+1}",
            "status": "Connecting",
            "last_seen": 0
        }
        self.nodes.append(node)
        # Immediate sync attempt
        self._sync_node(node)

    def remove_node(self, url):
        self.nodes = [n for n in self.nodes if n['url'] != url]

    def _generate_signature(self, endpoint, data_str, timestamp):
        """Generates an HMAC-SHA256 signature for the request."""
        message = f"{endpoint}|{timestamp}|{data_str}".encode()
        return hmac.new(self.secret_token.encode(), message, hashlib.sha256).hexdigest()

    def _sync_node(self, node):
        """Fetches radar data from a remote node with signed headers."""
        try:
            timestamp = str(int(time.time()))
            endpoint = "/api/radar"
            # For GET requests, data_str is empty
            signature = self._generate_signature(endpoint, "", timestamp)
            
            headers = {
                "X-Kharma-Token": node['token'],
                "X-Kharma-Timestamp": timestamp,
                "X-Kharma-Signature": signature
            }
            
            resp = requests.get(f"{node['url']}{endpoint}", headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json().get('data', [])
                self.hive_data[node['url']] = data
                node['status'] = "Online"
                node['last_seen'] = time.time()
                return True
            else:
                node['status'] = f"Error ({resp.status_code})"
        except Exception as e:
            node['status'] = "Offline"
        return False

    def broadcast_block(self, ip):
        """Broadcasts a signed BLOCK command to all nodes in the hive."""
        timestamp = str(int(time.time()))
        endpoint = "/api/swarm/block"
        payload = json.dumps({"ip": ip})
        
        for node in self.nodes:
            try:
                signature = self._generate_signature(endpoint, payload, timestamp)
                headers = {
                    "X-Kharma-Token": node['token'],
                    "X-Kharma-Timestamp": timestamp,
                    "X-Kharma-Signature": signature,
                    "Content-Type": "application/json"
                }
                requests.post(f"{node['url']}{endpoint}", headers=headers, data=payload, timeout=3)
            except:
                pass # Fire and forget for now

    def sync_all(self):
        """Standardizes a background sync for all nodes."""
        for node in self.nodes:
            self._sync_node(node)

    def get_hive_summary(self):
        """Returns consolidated stats across all nodes."""
        total_connections = 0
        total_threats = 0
        nodes_status = []
        
        for node in self.nodes:
            data = self.hive_data.get(node['url'], [])
            total_connections += len(data)
            total_threats += len([c for c in data if c.get('is_malware')])
            nodes_status.append({
                "name": node['name'],
                "url": node['url'],
                "status": node['status'],
                "connections": len(data),
                "threats": len([c for c in data if c.get('is_malware')])
            })
            
        return {
            "total_nodes": len(self.nodes),
            "hive_connections": total_connections,
            "hive_threats": total_threats,
            "nodes": nodes_status
        }
