import sqlite3
import time
from typing import Dict, List, Optional, Tuple

DB_FILENAME = "totally_not_my_privateKeys.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILENAME, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
        """
    )
    conn.commit()


def insert_key(conn: sqlite3.Connection, key_pem: bytes, exp_ts: int) -> int:
    cur = conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key_pem, exp_ts))
    conn.commit()
    return int(cur.lastrowid)


def get_one_key(conn: sqlite3.Connection, want_expired: bool) -> Optional[Tuple[int, bytes, int]]:
    now = int(time.time())
    if want_expired:
        row = conn.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
            (now,),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1",
            (now,),
        ).fetchone()
    return row  # (kid, key, exp) or None


def get_all_valid_keys(conn: sqlite3.Connection) -> List[Tuple[int, bytes, int]]:
    now = int(time.time())
    rows = conn.execute(
        "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid ASC",
        (now,),
    ).fetchall()
    return rows


def count_valid_and_expired(conn: sqlite3.Connection) -> Dict[str, int]:
    now = int(time.time())
    valid = conn.execute("SELECT COUNT(*) FROM keys WHERE exp > ?", (now,)).fetchone()[0]
    expired = conn.execute("SELECT COUNT(*) FROM keys WHERE exp <= ?", (now,)).fetchone()[0]
    return {"valid": valid, "expired": expired}