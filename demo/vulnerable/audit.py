"""DELIBERATELY VULNERABLE. Audit trail that can be rewritten."""

import sqlite3


def erase_trace(conn: sqlite3.Connection, actor: str):
    """MCP layer: the record of what happened is mutable, so an incident
    cannot be reconstructed afterwards."""
    conn.execute("DELETE FROM audit_logs WHERE actor = ?", (actor,))
    conn.commit()


def rewrite_entry(conn: sqlite3.Connection, entry_id: int, text: str):
    conn.execute("UPDATE audit_logs SET detail = ? WHERE id = ?", (text, entry_id))
    conn.commit()
