import os
import time
import requests
import tarfile
import maxminddb
from rich.console import Console

console = Console()

class GeoIPResolver:
    """
    Resolves IP addresses to their Geographical location using a local MaxMind database.
    This provides instant (0ms lag) lookups without ratelimits or privacy concerns.
    """
    def __init__(self):
        self.config_dir = os.path.expanduser('~/.kharma')
        os.makedirs(self.config_dir, exist_ok=True)
        self.db_path = os.path.join(self.config_dir, 'GeoLite2-City.mmdb')
        self.reader = None
        
        # Free public mirror for the MaxMind GeoLite2 City database (updated monthly)
        # We use a reliable mirror since MaxMind requires an account key now
        self.db_url = "https://git.io/GeoLite2-City.mmdb"
        
        self.private_prefixes = ('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', 
                                  '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', 
                                  '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')
                                  
        self._ensure_db()

    def _ensure_db(self):
        """Downloads the database on first run if it doesn't exist."""
        if not os.path.exists(self.db_path):
            console.print("[yellow]First run detected! Downloading offline GeoIP Database (~30MB)...[/yellow]")
            console.print("[dim]This will eliminate lag and protect your privacy.[/dim]")
            try:
                # GitHub mirror for the mmdb file
                # If git.io link ever breaks, we fallback to a known release asset
                url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
                response = requests.get(url, stream=True)
                response.raise_for_status()
                
                with open(self.db_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                console.print("[green]Database downloaded successfully![/green]")
            except Exception as e:
                console.print(f"[red]Failed to download database: {e}[/red]")
                
        try:
            if os.path.exists(self.db_path):
                self.reader = maxminddb.open_database(self.db_path)
        except Exception as e:
            console.print(f"[red]Error opening GeoIP Database: {e}[/red]")

    def resolve(self, ip_address):
        """Returns the Country and City for a given IP address."""
        if not ip_address:
            return "Unknown"
            
        if self._is_private(ip_address):
            return "Local Network"

        if not self.reader:
            return "DB Error"

        try:
            match = self.reader.get(ip_address)
            if match:
                country = match.get('country', {}).get('iso_code', '')
                if not country and 'registered_country' in match:
                    country = match['registered_country'].get('iso_code', '')
                
                # Try english name if iso code fails
                if not country:
                    country = match.get('country', {}).get('names', {}).get('en', '')
                    
                city = match.get('city', {}).get('names', {}).get('en', '')
                
                location = f"{city}, {country}".strip(', ')
                if not location:
                    location = "Unknown Location"
                    
                return location
            else:
                return "Unknown"
        except ValueError:
            return "Invalid IP"
        except Exception as e:
            return "Lookup Error"

    def _is_private(self, ip_address):
        return ip_address.startswith(self.private_prefixes) or ip_address in ('127.0.0.1', '::1')
        
    def close(self):
        if self.reader:
            self.reader.close()
