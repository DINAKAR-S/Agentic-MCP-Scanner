#!/usr/bin/env python3
"""Publish to PyPI with a keywarden-injected token.

keywarden stores the token under the generic-bearer provider, which injects it as
API_TOKEN. twine reads TWINE_PASSWORD. This bridges the two inside the child
process, so the value goes environment to environment and is never printed,
logged, or written to disk.

    keywarden run --inject pypi/prod -- python benchmark/_publish.py --check
    keywarden run --inject pypi/prod -- python benchmark/_publish.py dist/*

--check validates the plumbing without uploading anything.
"""

import glob
import os
import subprocess
import sys


def main() -> int:
    token = os.environ.get("API_TOKEN") or os.environ.get("TWINE_PASSWORD")
    if not token:
        print("ERROR: no token was injected. Expected API_TOKEN or TWINE_PASSWORD.",
              file=sys.stderr)
        return 2

    # Describe the token without revealing it. Enough to diagnose, never the value.
    stripped = token.strip()
    print(f"token received: {len(token)} characters")
    if stripped != token:
        print("  ! it has leading or trailing whitespace, which will be sent verbatim")
    if stripped.startswith("pypi-"):
        print("  ok: starts with 'pypi-'")
    else:
        head = stripped[:5]
        kind = ("looks base64-ish; a PyPI token's body is base64 but the 'pypi-' prefix "
                "must be included too" if head.isalnum() else "unrecognised")
        print(f"  ! does not start with 'pypi-'. First 5 characters are "
              f"{'alphanumeric' if head.isalnum() else 'non-alphanumeric'}; {kind}")
    token = stripped

    args = [a for a in sys.argv[1:] if a != "--check"]
    files = []
    for a in args:
        files.extend(glob.glob(a) if any(c in a for c in "*?[") else [a])
    files = [f for f in files if os.path.isfile(f)]

    if "--check" in sys.argv:
        print(f"artifacts that would be uploaded: {len(files)}")
        for f in files:
            print(f"  {os.path.basename(f)}  {os.path.getsize(f)} bytes")
        print("check only, nothing uploaded")
        return 0

    if not files:
        print("ERROR: no artifacts to upload.", file=sys.stderr)
        return 2

    env = dict(os.environ)
    env["TWINE_USERNAME"] = "__token__"
    env["TWINE_PASSWORD"] = token
    env["TWINE_NON_INTERACTIVE"] = "1"
    env.pop("API_TOKEN", None)

    print(f"uploading {len(files)} artifact(s) to PyPI ...")
    return subprocess.call(
        [sys.executable, "-m", "twine", "upload", "--disable-progress-bar", *files],
        env=env,
    )


if __name__ == "__main__":
    raise SystemExit(main())
