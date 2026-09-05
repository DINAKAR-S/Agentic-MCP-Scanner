# mcpvuln as a container. Detection is offline; no key or network is needed.
#
#   docker run --rm -v "$PWD:/scan" ghcr.io/dinakar-s/mcpvuln /scan
#
FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/DINAKAR-S/Agentic-MCP-Scanner"
LABEL org.opencontainers.image.description="Vulnerability detection for Model Context Protocol codebases"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY mcp-scan/ /app/
RUN pip install --no-cache-dir . && rm -rf /root/.cache

# Scans run as an unprivileged user against a bind-mounted checkout.
RUN useradd --create-home --uid 1000 scanner
USER scanner
WORKDIR /scan

ENTRYPOINT ["mcpvuln"]
CMD ["--help"]
