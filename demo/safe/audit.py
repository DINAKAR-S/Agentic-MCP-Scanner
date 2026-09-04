"""The same audit layer as demo/vulnerable, with every issue fixed.

The table is append-only and each row is hash-chained to its predecessor, so a
deletion or edit is detectable rather than silent.
"""

import hashlib
import sqlite3


def append_entry(conn: sqlite3.Connection, actor: str, detail: str, prev_hash: str):
    row = f"{actor}|{detail}|{prev_hash}".encode()
    digest = hashlib.sha256(row).hexdigest()
    conn.execute(
        "INSERT INTO audit_logs (actor, detail, prev_hash, digest) VALUES (?, ?, ?, ?)",
        (actor, detail, prev_hash, digest),
    )
    conn.commit()
    return digest
