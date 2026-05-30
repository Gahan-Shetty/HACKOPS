# backend/database/db.py
import sqlite3
import os

DB_PATH = os.getenv("DB_PATH", "./droidwatch.db")

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            apk_name TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            scan_id TEXT,
            layer TEXT,
            type TEXT,
            severity TEXT,
            description TEXT,
            details TEXT,
            raw TEXT,
            mitre_technique TEXT,
            defense_triggered INTEGER DEFAULT 0,
            timestamp TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
    """)
    conn.commit()
    conn.close()
