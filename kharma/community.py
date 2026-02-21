import os
import json
import time

class CommunityIntel:
    """
    Manages the crowdsourced blacklist. 
    Handles local reporting of IPs and synchronizes with the community feed.
    """
    def __init__(self):
        self.config_dir = os.path.expanduser('~/.kharma')
        os.makedirs(self.config_dir, exist_ok=True)
        self.blacklist_path = os.path.join(self.config_dir, 'community_blacklist.json')
        self.blacklist = {}
        self._load_blacklist()

    def _load_blacklist(self):
        """Loads the community blacklist from the local JSON file."""
        if os.path.exists(self.blacklist_path):
            try:
                with open(self.blacklist_path, 'r') as f:
                    self.blacklist = json.load(f)
            except Exception:
                self.blacklist = {}
        else:
            self.blacklist = {}

    def _save_blacklist(self):
        """Saves current blacklist state to disk."""
        try:
            with open(self.blacklist_path, 'w') as f:
                json.dump(self.blacklist, f, indent=4)
        except Exception as e:
            print(f"Error saving community blacklist: {e}")

    def report_ip(self, ip, reason="Community Report", severity="high"):
        """
        Reports an IP to the community. 
        In this local-first version, it adds it to the user's local community cache.
        """
        if not ip:
            return False
            
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        
        # If IP already exists, we increment the report count
        if ip in self.blacklist:
            self.blacklist[ip]['reports'] += 1
            self.blacklist[ip]['last_seen'] = timestamp
        else:
            self.blacklist[ip] = {
                'reason': reason,
                'severity': severity,
                'reports': 1,
                'first_seen': timestamp,
                'last_seen': timestamp
            }
            
        self._save_blacklist()
        return True

    def is_flagged(self, ip):
        """Checks if an IP has been flagged by the community."""
        if not ip:
            return False
        return ip in self.blacklist

    def get_details(self, ip):
        """Returns community details for a flagged IP."""
        return self.blacklist.get(ip)

    def sync(self):
        """
        Future implementation: Sync local reporting with a central Kharma Master Feed.
        For now, this is a placeholder for decentralized sharing.
        """
        pass
