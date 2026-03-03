import requests
import json
import os
import time

class ReputationEngine:
    """
    Kharma Elite Reputation Engine (Phase 12).
    Integrates with AbuseIPDB to fetch live reputation scores for remote IPs.
    """
    def __init__(self, forensics_db):
        self.db = forensics_db
        self.api_key = self.db.get_encrypted_setting("abuse_ipdb_key")
        self.cache_ttl = 86400 # 24 hours
        
    def get_score(self, ip):
        """
        Fetches the abuse confidence score for an IP.
        Uses local cache first to minimize API calls.
        """
        if not ip or ip in ['127.0.0.1', '0.0.0.0', 'localhost', '::1']:
            return 0
            
        # 1. Check Cache
        cached = self.db.get_setting(f"rep_{ip}")
        if cached:
            data = json.loads(cached)
            if time.time() - data['ts'] < self.cache_ttl:
                return data['score']
                
        # 2. Fetch from AbuseIPDB (Simulated fallback if no key)
        if not self.api_key:
            return 0 # Silent fail if no key configured
            
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            querystring = {
                'ipAddress': ip,
                'maxAgeInDays': '90',
                'verbose': 'true' # Get extra metadata
            }
            headers = {
                'Accept': 'application/json',
                'Key': self.api_key
            }
            response = requests.get(url, headers=headers, params=querystring, timeout=5)
            if response.status_code == 200:
                data = response.json()
                score = data['data']['abuseConfidenceScore']
                
                # AIR Enrichment (Phase 13)
                enrichment = {
                    'score': score,
                    'ts': time.time(),
                    'org': data['data'].get('domain', 'Private/Internal'),
                    'isp': data['data'].get('isp', 'Unknown ISP'),
                    'usage_type': data['data'].get('usageType', 'Unknown'),
                    'is_tor': data['data'].get('isTor', False)
                }
                
                # Cache the full enrichment
                self.db.set_setting(f"rep_{ip}", json.dumps(enrichment))
                return score
        except Exception as e:
            print(f"[REPUTATION] API Error: {e}")
            
        return 0

    def get_full_intel(self, ip):
        """Returns the full cached intelligence for an IP (score + org + isp)."""
        cached = self.db.get_setting(f"rep_{ip}")
        if cached:
            return json.loads(cached)
        # Fallback if not cached (trigger a check if key exists)
        if self.api_key:
            self.get_score(ip)
            cached = self.db.get_setting(f"rep_{ip}")
            if cached: return json.loads(cached)
        return {"score": 0, "org": "Unknown", "isp": "Unknown", "ts": 0}
