"""The same server as demo/vulnerable, with every issue fixed.

Scanning this should produce no findings. That is the point: a scanner that
fires on both is not measuring anything.
"""

import os
import secrets
import sqlite3
import subprocess

from openai import OpenAI

# Fixed: the cache key is bound to the tenant, so no context crosses a boundary.
_tenant_context = {}

# Fixed: the credential comes from the environment, not from source.
DATABASE_PASSWORD = os.environ["DATABASE_PASSWORD"]

client = OpenAI()


def lookup_customer(cursor: sqlite3.Cursor, name: str):
    """Fixed: the value is bound by the driver, never interpolated."""
    cursor.execute("SELECT * FROM customers WHERE name = ?", (name,))
    return cursor.fetchall()


def check_host(hostname: str):
    """Fixed: an argument list, no shell."""
    subprocess.run(["ping", "-c", "1", hostname], shell=False, check=False)


def run_report(report_name: str):
    """Fixed: an argument list, no shell."""
    return subprocess.run(["generate_report", report_name], shell=False, check=False)


def load_snapshot(blob: bytes):
    """Fixed: a data format that cannot execute code."""
    import json
    return json.loads(blob)


def answer(user_message: str, retrieved_page: str):
    """Fixed: untrusted text stays in a user-role message."""
    return client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": user_message},
        ],
    )


def cache_context(tenant_id: str, request_id: str, ctx: dict):
    """Fixed: a composite, tenant-bound key."""
    _tenant_context[(tenant_id, request_id)] = ctx
    return _tenant_context[(tenant_id, request_id)]


def fetch_upstream(path: str):
    """Fixed: TLS."""
    import requests
    return requests.get("https://mcp-registry.internal.example/" + path, timeout=10)


def new_session_id() -> str:
    """Fixed: a cryptographic source for a security-relevant value."""
    return secrets.token_urlsafe(32)
