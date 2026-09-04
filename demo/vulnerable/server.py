"""DELIBERATELY VULNERABLE. Do not copy any of this into a real system.

A small MCP server that looks like plenty of real ones, carrying one instance of
each vulnerability class the scanner detects. Its fixed twin lives in
``demo/safe/`` and should produce no findings at all.

    mcpvuln demo/vulnerable     # should find these
    mcpvuln demo/safe           # should stay quiet
"""

import os
import sqlite3
import subprocess

from openai import OpenAI

# --- MCP layer: a session cache with no tenant in the key ---------------------
# Under concurrent load one tenant's context is served to another.
session_cache = {}

# --- Traditional web: a credential in source ---------------------------------
DATABASE_PASSWORD = "pG7xR2mQvL9aZ4kT8nW1"

client = OpenAI()


def lookup_customer(cursor: sqlite3.Cursor, name: str):
    """Traditional web: SQL assembled by string formatting."""
    cursor.execute("SELECT * FROM customers WHERE name = '%s'" % name)
    return cursor.fetchall()


def check_host(hostname: str):
    """Traditional web: user input concatenated into a shell command."""
    os.system("ping -c 1 " + hostname)


def run_report(report_name: str):
    """Traditional web: shell=True on a caller-supplied value."""
    return subprocess.run("generate_report " + report_name, shell=True, check=False)


def load_snapshot(blob: bytes):
    """Traditional web: deserialising bytes from an untrusted source."""
    import pickle
    return pickle.loads(blob)


def answer(user_message: str, retrieved_page: str):
    """LLM layer: untrusted text placed where the model reads instructions."""
    system_prompt = "You are a helpful assistant. Context: " + user_message
    return client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "system", "content": system_prompt}],
    )


def cache_context(request_id: str, ctx: dict):
    """MCP layer: the cache key is not bound to a tenant."""
    session_cache["context"] = ctx
    return session_cache["context"]


def fetch_upstream(path: str):
    """MCP layer: plaintext transport to a non-loopback host."""
    import requests
    return requests.get("http://mcp-registry.internal.example/" + path)
