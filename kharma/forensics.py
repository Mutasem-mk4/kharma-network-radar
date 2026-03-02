import sqlite3
import os
import json
import csv
import io
import time
from cryptography.fernet import Fernet

DB_PATH = os.path.join(os.path.expanduser("~"), ".kharma", "forensics.db")

class ForensicsDB:
    """
    Kharma Forensics — Persistent event logging using SQLite.
    Records all security events: threats, blocks, and DPI alerts.
    """

    def __init__(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self.db_path = DB_PATH
        self._init_db()
        self._init_encryption()

    def _init_encryption(self):
        """Initializes the master encryption key."""
        key_path = os.path.join(os.path.dirname(self.db_path), "secret.key")
        if not os.path.exists(key_path):
            key = Fernet.generate_key()
            with open(key_path, 'wb') as f:
                f.write(key)
        else:
            with open(key_path, 'rb') as f:
                key = f.read()
        self.fernet = Fernet(key)

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Return dict-like rows
        return conn

    def _init_db(self):
        """Creates the events table if it doesn't exist."""
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT NOT NULL,
                    event_type  TEXT NOT NULL,
                    ip          TEXT,
                    process     TEXT,
                    location    TEXT,
                    detail      TEXT,
                    severity    TEXT DEFAULT 'medium'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key         TEXT PRIMARY KEY,
                    value       TEXT NOT NULL
                )
            """)
            conn.commit()

    def log(self, event_type, ip=None, process=None, location=None, detail=None, severity="medium"):
        """
        Logs a new security event.
        event_type: 'THREAT' | 'BLOCKED' | 'DPI_ALERT' | 'COMMUNITY_FLAG'
        """
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO events (timestamp, event_type, ip, process, location, detail, severity) VALUES (?,?,?,?,?,?,?)",
                (timestamp, event_type, ip, process, location, detail, severity)
            )
            conn.commit()

    def get_events(self, limit=200, event_type=None):
        """Returns the most recent events, optionally filtered by type."""
        with self._connect() as conn:
            if event_type:
                rows = conn.execute(
                    "SELECT * FROM events WHERE event_type=? ORDER BY id DESC LIMIT ?",
                    (event_type, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM events ORDER BY id DESC LIMIT ?",
                    (limit,)
                ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self):
        """Returns aggregate counts per event type."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT event_type, COUNT(*) as count FROM events GROUP BY event_type"
            ).fetchall()
        return {r["event_type"]: r["count"] for r in rows}

    def export_csv(self):
        """Exports all events as a CSV string."""
        events = self.get_events(limit=10000)
        if not events:
            return ""
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=events[0].keys())
        writer.writeheader()
        writer.writerows(events)
        return output.getvalue()

    def export_json(self):
        """Exports all events as a JSON string."""
        events = self.get_events(limit=10000)
        return json.dumps(events, indent=2)

    def clear(self):
        """Deletes all events (useful for resetting)."""
        with self._connect() as conn:
            conn.execute("DELETE FROM events")
            conn.commit()

    def set_setting(self, key, value):
        """Persists a setting as a string/JSON."""
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (key, str(value))
            )
            conn.commit()

    def get_setting(self, key, default=None):
        """Retrieves a persistent setting."""
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            if row:
                return row["value"]
        return default

    def set_encrypted_setting(self, key, value):
        """Encrypt and store a sensitive setting."""
        if not value: return
        encrypted = self.fernet.encrypt(str(value).encode()).decode()
        self.set_setting(key, encrypted)

    def get_encrypted_setting(self, key, default=None):
        """Retrieve and decrypt a sensitive setting."""
        val = self.get_setting(key)
        if not val: return default
        try:
            return self.fernet.decrypt(val.encode()).decode()
        except:
            return default
