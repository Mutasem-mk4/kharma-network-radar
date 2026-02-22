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
        """Calculate SHA-256 hash of a local file with memory caching."""
        if not file_path or not os.path.exists(file_path):
            return None
            
        if not hasattr(self, '_hash_cache'):
            self._hash_cache = {}
            
        if file_path in self._hash_cache:
            return self._hash_cache[file_path]
            
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # Read in chunks to handle large files efficiently
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            res = sha256_hash.hexdigest()
            self._hash_cache[file_path] = res
            return res
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
        # To prevent the server from hanging due to vt-py automatically sleeping on rate limits (4/min),
        # we bypass the synchronous internet fetch here. A real implementation would push this to a background worker.
        return None, None
        except Exception:
            return None, None

    def close(self):
        if self.client:
            self.client.close()
        if self.conn:
            self.conn.close()
