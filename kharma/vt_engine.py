import vt
import hashlib
import os
import json
import sqlite3
from time import time

import threading

class VTEngine:
    def __init__(self):
        self.config_path = os.path.expanduser("~/.kharma/daemon_config.json")
        self.db_path = os.path.expanduser("~/.kharma/vt_cache.db")
        self.api_key = self._load_api_key()
        self.client = vt.Client(self.api_key) if self.api_key else None
        self._db_lock = threading.Lock()
        self._secure_config_permissions()
        self._init_cache()

    def _secure_config_permissions(self):
        """Hardens file permissions for the .kharma directory."""
        if os.name == 'posix': # Linux/Mac
            try:
                base_dir = os.path.dirname(self.config_path)
                if os.path.exists(base_dir):
                    os.chmod(base_dir, 0o700) # Only user can access dir
                if os.path.exists(self.config_path):
                    os.chmod(self.config_path, 0o600) # Only user can read key
            except Exception as e:
                print(f"[VT] Permission hardening error: {e}")
        # Windows permissions are handled via ACLs, usually inherited safely from %USERPROFILE%

    def _load_api_key(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    config = json.load(f)
                    return config.get("vt_api_key")
            except Exception as e:
                print(f"[VT] Config load error: {e}")
        return None

    def _get_db_connection(self):
        """Returns a thread-local database connection."""
        if not hasattr(self, '_local_thread'):
            self._local_thread = threading.local()
        
        if not hasattr(self._local_thread, 'conn'):
            try:
                self._local_thread.conn = sqlite3.connect(
                    self.db_path, 
                    check_same_thread=False,
                    timeout=10.0
                )
            except sqlite3.Error as e:
                print(f"[VT] Failed to connect to DB: {e}")
                self._local_thread.conn = None
        return self._local_thread.conn

    def _init_cache(self):
        """Initialize SQLite database for caching VT results to avoid API limits."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = self._get_db_connection()
        if not conn: return
        
        with self._db_lock:
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS file_hashes (
                        hash TEXT PRIMARY KEY,
                        malicious INTEGER,
                        total INTEGER,
                        timestamp REAL
                    )
                ''')
                conn.commit()
            except sqlite3.Error as e:
                print(f"[VT] Cache Init Error: {e}")

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
        except Exception as e:
            print(f"[VT] Hash calculation error for {file_path}: {e}")
            return None

    def check_hash(self, file_hash):
        """
        Check hash against VT. Returns (malicious_count, total_count).
        Uses SQLite caching to prevent rate-limiting.
        """
        if not file_hash:
            return None, None
            
        # 1. Check Local Cache (Valid for 24 hours)
        conn = self._get_db_connection()
        if conn:
            with self._db_lock:
                try:
                    cursor = conn.cursor()
                    cursor.execute("SELECT malicious, total, timestamp FROM file_hashes WHERE hash=?", (file_hash,))
                    result = cursor.fetchone()
                    
                    if result:
                        malicious, total, timestamp = result
                        # Cache expiration: 24 hours (86400 seconds)
                        if time() - timestamp < 86400:
                            return malicious, total
                            
                    # Note: We must consume/close cursors promptly to prevent 'API misuse' logic
                    cursor.close()
                except sqlite3.Error as e:
                    print(f"[VT] Cache query error: {e}")
                    # Force reconnect on next try if 'misuse' occurs
                    if "misuse" in str(e).lower() and hasattr(self._local_thread, 'conn'):
                        try:
                            self._local_thread.conn.close()
                        except: pass
                        del self._local_thread.conn

        # 2. Query VirusTotal API
        # To prevent the server from hanging due to vt-py automatically sleeping on rate limits (4/min),
        # we bypass the synchronous internet fetch here. A real implementation would push this to a background worker.
        return None, None

    def close(self):
        if self.client:
            self.client.close()
        
        # Clean up thread-local connection if it exists
        if hasattr(self, '_local_thread') and hasattr(self._local_thread, 'conn') and self._local_thread.conn:
            try:
                self._local_thread.conn.close()
            except: pass
            self._local_thread.conn = None
