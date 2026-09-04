#!/bin/sh
# The same installer as demo/vulnerable, with every issue fixed.
# Download, verify the checksum, then execute.
set -eu
curl -sSL -o agent.sh https://install.example.invalid/agent.sh
echo "${AGENT_SHA256}  agent.sh" | sha256sum -c -
sh ./agent.sh
