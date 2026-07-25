"""SQLite database setup and connection management for SentinelDNA."""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "sentinel.db")


def get_connection() -> sqlite3.Connection:
    """Return a SQLite connection with row_factory set for dict-like rows."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = get_connection()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS identities (
                entity_id    TEXT PRIMARY KEY,
                entity_type  TEXT NOT NULL,
                department   TEXT,
                profile      TEXT NOT NULL,
                created_at   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS events (
                event_id          TEXT PRIMARY KEY,
                entity_id         TEXT NOT NULL,
                entity_type       TEXT NOT NULL,
                timestamp         TEXT NOT NULL,
                source_ip         TEXT NOT NULL,
                geo_location      TEXT NOT NULL,
                latitude          REAL NOT NULL,
                longitude         REAL NOT NULL,
                resource_accessed TEXT NOT NULL,
                auth_method       TEXT NOT NULL,
                auth_success      INTEGER NOT NULL,
                session_duration  REAL NOT NULL,
                command_sequence  TEXT NOT NULL,
                device_fingerprint TEXT NOT NULL,
                department        TEXT,
                label             TEXT NOT NULL,
                FOREIGN KEY (entity_id) REFERENCES identities(entity_id)
            );

            CREATE INDEX IF NOT EXISTS idx_events_entity_id  ON events(entity_id);
            CREATE INDEX IF NOT EXISTS idx_events_label       ON events(label);
            CREATE INDEX IF NOT EXISTS idx_events_entity_type ON events(entity_type);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp   ON events(timestamp);
        """)
        conn.commit()
    finally:
        conn.close()


def drop_all():
    """Drop all tables (used before regeneration)."""
    conn = get_connection()
    try:
        conn.executescript("""
            DROP TABLE IF EXISTS events;
            DROP TABLE IF EXISTS identities;
        """)
        conn.commit()
    finally:
        conn.close()
