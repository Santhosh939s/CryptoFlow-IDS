import sqlite3
import os
import time
from typing import List, Dict, Any, Optional

DB_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cryptoflow.db")

class Database:
    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self.init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        """Creates necessary database tables if they do not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    datetime_str TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    entropy REAL,
                    packet_size INTEGER,
                    payload_len INTEGER,
                    protocol TEXT,
                    is_quic INTEGER,
                    confidence REAL,
                    mitigated INTEGER,
                    country TEXT DEFAULT 'Unknown',
                    country_code TEXT DEFAULT 'LOC',
                    flag TEXT DEFAULT '🧪',
                    asn TEXT DEFAULT 'AS-LOCAL',
                    threat_score INTEGER DEFAULT 85,
                    pcap_file TEXT
                )
            """)

            # Safe column migrations for existing SQLite databases
            migration_cols = [
                ("country", "TEXT DEFAULT 'Unknown'"),
                ("country_code", "TEXT DEFAULT 'LOC'"),
                ("flag", "TEXT DEFAULT '🧪'"),
                ("asn", "TEXT DEFAULT 'AS-LOCAL'"),
                ("threat_score", "INTEGER DEFAULT 85"),
                ("pcap_file", "TEXT")
            ]
            for col_name, col_type in migration_cols:
                try:
                    cursor.execute(f"ALTER TABLE threat_logs ADD COLUMN {col_name} {col_type}")
                except Exception:
                    pass

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE,
                    blocked_at REAL,
                    datetime_str TEXT,
                    reason TEXT,
                    is_active INTEGER DEFAULT 1
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS session_stats (
                    key TEXT PRIMARY KEY,
                    value INTEGER
                )
            """)
            conn.commit()

    def log_threat(self, src_ip: str, dst_ip: str, dst_port: int, entropy: float,
                   packet_size: int, payload_len: int, protocol: str, is_quic: bool,
                   confidence: float, mitigated: bool,
                   country: str = "Unknown", country_code: str = "LOC", flag: str = "🧪",
                   asn: str = "AS-LOCAL", threat_score: int = 85, pcap_file: Optional[str] = None) -> int:
        now = time.time()
        dt_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO threat_logs (
                    timestamp, datetime_str, src_ip, dst_ip, dst_port,
                    entropy, packet_size, payload_len, protocol, is_quic,
                    confidence, mitigated, country, country_code, flag, asn, threat_score, pcap_file
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                now, dt_str, src_ip, dst_ip, dst_port,
                round(entropy, 4), packet_size, payload_len, protocol,
                1 if is_quic else 0, round(confidence, 4) if confidence else 1.0,
                1 if mitigated else 0,
                country, country_code, flag, asn, threat_score, pcap_file
            ))
            conn.commit()
            return cursor.lastrowid

    def update_threat_pcap(self, threat_id: int, pcap_file: str):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE threat_logs SET pcap_file = ? WHERE id = ?", (pcap_file, threat_id))
            conn.commit()

    def update_threat_intel(self, threat_id: int, country: str, country_code: str,
                            flag: str, asn: str, threat_score: int):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE threat_logs
                SET country = ?, country_code = ?, flag = ?, asn = ?, threat_score = ?
                WHERE id = ?
            """, (country, country_code, flag, asn, threat_score, threat_id))
            conn.commit()

    def get_recent_threats(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM threat_logs ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def log_blocked_ip(self, ip: str, reason: str = "High-entropy exfiltration"):
        now = time.time()
        dt_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO blocked_ips (ip, blocked_at, datetime_str, reason, is_active)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(ip) DO UPDATE SET
                    blocked_at=excluded.blocked_at,
                    datetime_str=excluded.datetime_str,
                    reason=excluded.reason,
                    is_active=1
            """, (ip, now, dt_str, reason))
            conn.commit()

    def remove_blocked_ip(self, ip: str):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE blocked_ips SET is_active=0 WHERE ip=?
            """, (ip,))
            conn.commit()

    def get_active_blocked_ips(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM blocked_ips WHERE is_active=1 ORDER BY blocked_at DESC
            """)
            return [dict(row) for row in cursor.fetchall()]

    def get_stats_summary(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as total FROM threat_logs")
            total_threats = cursor.fetchone()["total"]

            cursor.execute("SELECT COUNT(*) as active FROM blocked_ips WHERE is_active=1")
            active_blocked = cursor.fetchone()["active"]

            cursor.execute("SELECT COUNT(*) as quic_count FROM threat_logs WHERE is_quic=1")
            quic_threats = cursor.fetchone()["quic_count"]

            return {
                "total_threats": total_threats,
                "active_blocked": active_blocked,
                "quic_threats": quic_threats
            }

db = Database()
