"""Deliberately vulnerable MCP server: the classes disclosed as CVEs in 2025-2026.

Each function carries the shape of a published vulnerability. See
demo/ground-truth-2026.json for the instance list and the CVE each one mirrors.
Nothing here is imported by the scanner or by any test as live code.
"""

import asyncio
import hashlib
import sqlite3

import requests
from git import Repo
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

mcp = FastMCP("demo-2026")

# CVE-2025-66416: the SDK protects localhost by default; this switches it off.
mcp.settings.transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=False,
)

ALLOWED_ROOT = "/srv/data"


@mcp.tool()
def check_endpoint(url: str) -> str:
    """Fetch a URL and report the status. CVE-2025-65513 shape."""
    response = requests.get(url, timeout=5)
    return f"{response.status_code} {response.text[:200]}"


@mcp.tool()
async def run_tests(target: str) -> str:
    """Run pytest on a target. The target lands in a shell string."""
    command = f"python -m pytest {target}"
    process = await asyncio.create_subprocess_shell(command)
    out, _ = await process.communicate()
    return out.decode()[:2000]


@mcp.tool()
def shell(command: str, cwd: str = "/") -> str:
    """Run any command. An argument list that starts a shell is still a shell."""
    import subprocess
    proc = subprocess.Popen(["bash", "-lc", command], cwd=cwd)
    return str(proc.wait())


@mcp.tool()
def git_diff(repo_path: str, target: str, context_lines: int = 3) -> str:
    """CVE-2025-68144 shape: a target starting with '-' becomes a git option."""
    repo = Repo(repo_path)
    return repo.git.diff(f"--unified={context_lines}", target)


@mcp.tool()
def read_file(path: str) -> str:
    """CVE-2025-66689 shape: a string-prefix check on the raw path."""
    if not path.startswith(ALLOWED_ROOT):
        raise ValueError("outside the data root")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


@mcp.tool()
def login(user: str, password: str) -> bool:
    """MD5 over a password."""
    digest = hashlib.md5(password.encode()).hexdigest()
    return _stored_digest(user) == digest


@mcp.tool()
def list_actions(where: str, limit: int = 20) -> list:
    """A caller-shaped WHERE clause interpolated into the statement."""
    db = sqlite3.connect("actions.db")
    rows = db.execute(f"SELECT * FROM actions {where} ORDER BY id LIMIT ?", (limit,))
    return rows.fetchall()


def _stored_digest(user: str) -> str:
    return ""


if __name__ == "__main__":
    # CVE-2026-23744 shape: every interface, nothing in front of it.
    mcp.run(transport="http", host="0.0.0.0", port=8000)
