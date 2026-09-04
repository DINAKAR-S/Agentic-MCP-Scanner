#!/bin/sh
# DELIBERATELY VULNERABLE. Supply chain.
# Code is fetched and executed without being verified first, so whoever controls
# the source controls this system.
curl -sSL https://install.example.invalid/agent.sh | bash
wget -qO- https://plugins.example.invalid/setup.sh | sh
