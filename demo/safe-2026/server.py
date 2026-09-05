"""The same server as demo/vulnerable-2026/server.py with each defect fixed.

Every finding the scanner reports on this file is a false positive.
"""

import asyncio
import hashlib
import ipaddress
import os
import socket
import sqlite3
from urllib.parse import urlparse

import requests
from git import Repo
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

mcp = FastMCP("demo-2026-fixed")

mcp.settings.transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=["127.0.0.1:*", "localhost:*"],
    allowed_origins=["http://127.0.0.1:*", "http://localhost:*"],
)

ALLOWED_ROOT = os.path.realpath("/srv/data")
ALLOWED_QUERIES = {
    "open": "SELECT * FROM actions WHERE status = 'open' ORDER BY id LIMIT ?",
    "all": "SELECT * FROM actions ORDER BY id LIMIT ?",
}


@mcp.tool()
def check_endpoint(url: str) -> str:
    """Fetch a URL, refusing private and link-local hosts."""
    host = urlparse(url).hostname or ""
    if ipaddress.ip_address(socket.gethostbyname(host)).is_private:
        raise ValueError("private address")
    response = requests.get(url, timeout=5, allow_redirects=False)
    return f"{response.status_code} {response.text[:200]}"


@mcp.tool()
async def run_tests(target: str) -> str:
    """Run pytest on a target without a shell."""
    process = await asyncio.create_subprocess_exec("python", "-m", "pytest", "--", target)
    out, _ = await process.communicate()
    return out.decode()[:2000]


@mcp.tool()
def git_diff(repo_path: str, target: str, context_lines: int = 3) -> str:
    """'--' ends option parsing, so a target starting with '-' stays a path."""
    if target.startswith("-"):
        raise ValueError("refusing an option-shaped target")
    repo = Repo(repo_path)
    return repo.git.diff(f"--unified={context_lines}", "--", target)


@mcp.tool()
def read_file(path: str) -> str:
    """Canonicalise first, then test containment."""
    real = os.path.realpath(path)
    if os.path.commonpath([real, ALLOWED_ROOT]) != ALLOWED_ROOT:
        raise ValueError("outside the data root")
    with open(real, encoding="utf-8") as fh:
        return fh.read()


@mcp.tool()
def login(user: str, password: str) -> bool:
    """SHA-256 here stands in for argon2 or bcrypt in a real system."""
    digest = hashlib.sha256(password.encode()).hexdigest()
    return _stored_digest(user) == digest


@mcp.tool()
def list_actions(filter_name: str, limit: int = 20) -> list:
    """The whole statement comes from an allow-list, never from the caller."""
    db = sqlite3.connect("actions.db")
    rows = db.execute(ALLOWED_QUERIES[filter_name], (limit,))
    return rows.fetchall()


def _stored_digest(user: str) -> str:
    return ""


if __name__ == "__main__":
    mcp.run(transport="http", host="127.0.0.1", port=8000)
