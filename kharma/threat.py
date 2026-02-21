import os
import requests
import time
from rich.console import Console

console = Console()

class ThreatIntelligence:
    """
    Downloads and caches a list of known malicious IP addresses from AlienVault OTX
    or other public threat feeds, allowing for instant offline lookups.
    """
    def __init__(self):
        self.config_dir = os.path.expanduser('~/.kharma')
        os.makedirs(self.config_dir, exist_ok=True)
        self.feed_path = os.path.join(self.config_dir, 'malware_ips.txt')
        self.malicious_ips = set()
        
        # Public blocklist maintained by Firehol (contains thousands of malicious IPs/botnets)
        self.feed_url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
        
        self.cache_ttl = 24 * 60 * 60 # 24 hours
        
        self._ensure_feed()
        self._load_feed()

    def _ensure_feed(self):
        """Downloads the threat feed if it doesn't exist or is older than 24 hours."""
        needs_download = False
        
        if not os.path.exists(self.feed_path):
            needs_download = True
            console.print("[yellow]First run: Downloading Malware Threat Intelligence Database...[/yellow]")
        else:
            file_age = time.time() - os.path.getmtime(self.feed_path)
            if file_age > self.cache_ttl:
                needs_download = True
                # Silent background update
                
        if needs_download:
            try:
                response = requests.get(self.feed_url, timeout=10)
                if response.status_code == 200:
                    with open(self.feed_path, 'w') as f:
                        f.write(response.text)
                    if not os.path.exists(self.feed_path):
                        console.print("[green]Threat Intelligence Downloaded. Kharma is armed.[/green]")
            except Exception as e:
                # Silently fail if updating, warn if first run
                if not os.path.exists(self.feed_path):
                    console.print(f"[red]Warning: Could not download Threat Intelligence: {e}[/red]")
                    console.print("[dim]Malware detection will be disabled temporarily.[/dim]")

    def _load_feed(self):
        """Loads the IPs from the text file into a fast Python Set for O(1) lookups."""
        if not os.path.exists(self.feed_path):
            return
            
        try:
            with open(self.feed_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    # Firehol feeds contain CIDR notations (e.g., 1.2.3.4/32)
                    # For simplicity and speed in this version, we'll exact match single IPs (/32)
                    # A robust version would use the `ipaddress` module to check if an IP is IN the subnet
                    self.malicious_ips.add(line.split('/')[0])
        except Exception:
            pass

    def check_ip(self, ip_address):
        """
        Returns True if the IP is found in the malicious database.
        Note: This is a fast, simplified check.
        """
        if not ip_address:
            return False
            
        return ip_address in self.malicious_ips

