import vt
import hashlib
import os
import json
import sqlite3
from time import time

class VTEngine:
    def __init__(self):
        self.config_path = os.path.expanduser("~/.kharma/daemon_config.json")
        self.db_path = os.path.expanduser("~/.kharma/vt_cache.db")
        self.api_key = self._load_api_key()
        self.client = vt.Client(self.api_key) if self.api_key else None
        self._init_cache()

    def _load_api_key(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    config = json.load(f)
                    return config.get("vt_api_key")
            except Exception:
                pass
        return None

    def _init_cache(self):
        """Initialize SQLite database for caching VT results to avoid API limits."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = self.conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_hashes (
                    hash TEXT PRIMARY KEY,
                    malicious INTEGER,
                    total INTEGER,
                    timestamp REAL
                )
            ''')
            self.conn.commit()
        except sqlite3.Error:
            self.conn = None

    def get_file_hash(self, file_path):
        """Calculate SHA-256 hash of a local file."""
        if not file_path or not os.path.exists(file_path):
            return None
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # Read in chunks to handle large files efficiently
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return None

    def check_hash(self, file_hash):
        """
        Check hash against VT. Returns (malicious_count, total_count).
        Uses SQLite caching to prevent rate-limiting.
        """
        if not file_hash:
            return None, None
            
        # 1. Check Local Cache (Valid for 24 hours)
        if self.conn:
            try:
                cursor = self.conn.cursor()
                cursor.execute("SELECT malicious, total, timestamp FROM file_hashes WHERE hash=?", (file_hash,))
                result = cursor.fetchone()
                if result:
                    malicious, total, timestamp = result
                    # Cache expiration: 24 hours (86400 seconds)
                    if time() - timestamp < 86400:
                        return malicious, total
            except sqlite3.Error:
                pass

        # 2. Query VirusTotal API
        if not self.client:
            return None, None

        try:
            # vt-py requires the ID to be the file hash
            file_obj = self.client.get_object(f"/files/{file_hash}")
            stats = file_obj.last_analysis_stats
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            
            # 3. Update Cache
            if self.conn:
                try:
                    cursor = self.conn.cursor()
                    cursor.execute("INSERT OR REPLACE INTO file_hashes (hash, malicious, total, timestamp) VALUES (?, ?, ?, ?)",
                                   (file_hash, malicious, total, time()))
                    self.conn.commit()
                except sqlite3.Error:
                    pass
                    
            return malicious, total
        except vt.APIError as e:
            # 404 means the file is unknown to VT (Not found)
            if e.code == 'NotFoundError':
                # Cache as clean to avoid re-querying unknown files immediately
                if self.conn:
                    try:
                        cursor = self.conn.cursor()
                        cursor.execute("INSERT OR REPLACE INTO file_hashes (hash, malicious, total, timestamp) VALUES (?, ?, ?, ?)",
                                       (file_hash, 0, 0, time()))
                        self.conn.commit()
                    except sqlite3.Error:
                        pass
                return 0, 0
            return None, None # API Limit or other error
        except Exception:
            return None, None

    def close(self):
        if self.client:
            self.client.close()
        if self.conn:
            self.conn.close()
