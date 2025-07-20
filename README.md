# MCP Vulnerability Analysis & Monitoring Pipeline

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/Security-Vulnerability%20Analysis-red.svg)](https://github.com/DINAKAR-S/Agentic-MCP-Scanner)

A comprehensive security analysis tool for Model Context Protocol (MCP) implementations and LLM-integrated systems. This pipeline combines automated code analysis, real-time threat intelligence, and AI-powered vulnerability assessment to identify both classic and MCP-specific security risks.

## Features

### Core Capabilities
- Multi-Agent Security Analysis 
- GitHub Repository Scanning 
- Real-time Threat Intelligence 
- MCP-Specific Detection 
- CVSS/SSVC Assessment 
- Markdown Report Generation 

### Vulnerability Detection
- Classic vulnerabilities: SQL injection, XSS, command injection, path traversal, etc.
- MCP-specific risks: Prompt injection, tool misuse, memory poisoning, credential harvesting.
- AI/LLM vulnerabilities, including model inversion, data poisoning, privilege escalation.
- Supply chain attacks and configuration issues.

## Prerequisites

- Python 3.8 or higher
- Google API Key (for Gemini integration)
- Firecrawl API Key (optional)

## Installation

### Option 1: Install from Source
```bash
git clone https://github.com/DINAKAR-S/Agentic-MCP-Scanner.git
cd Agentic-MCP-Scanner
pip install -r requirements.txt
```

### Option 2: Install Package
```bash
pip install -r requirements.txt
pip install .
```

## Configuration

Create a `.env` file in your project directory:
```env
GOOGLE_API_KEY=your_google_api_key_here
FIRECRAWL_API_KEY=your_firecrawl_api_key_here  # Optional
```

## Usage

### Command Line Interface

Scan one or more GitHub repositories:
```bash
mcpvuln https://github.com/user/repo1 https://github.com/user/repo2
```

### Python API
```python
from mcpvuln import SecurityAnalysisTeam

team = SecurityAnalysisTeam()
github_urls = ["https://github.com/user/repo1", "https://github.com/user/repo2"]
vuln_urls = ["https://threatsource.com", "https://security-blog.com"]

result = team.run_analysis(github_urls, vuln_urls)
print(f"Reports generated: {result['reports']}")
print(f"Vulnerabilities found: {result['vulnerabilities']}")
print(f"External threats: {result['external_vulns']}")
```

### Advanced Usage
```python
result = team.run_analysis(
    github_urls=["https://github.com/user/repo"],
    vuln_urls=["https://threatsource.com"],
    include_patterns=["*.py", "*.js"],
    exclude_patterns=["*.test.py", "node_modules/"],
    max_file_size=1024*1024,
    token="your_github_token"
)
```

## Output

Files generated:
- `{repo_name}_security_report.md` — Detailed security analysis report.
- `external_vulnerabilities.md` — Real-time threat intelligence summary.
- `vulnerabilities.txt` — Structured vulnerability listing.

Reports include:
- Executive Summary
- CVSS Scoring
- SSVC Framework
- Technical Analysis
- Mitigation Recommendations
- External Threat Context

## Architecture

### Multi-Agent Team
1. GitHub Scraper Agent
2. Vulnerability Analyzer Agent
3. Firecrawl Integration Agent
4. Report Generator Agent

Key components:
- agno (multi-agent framework)
- gitingest (repository ingestion)
- firecrawl (real-time threat intelligence)
- google-generativeai (advanced analysis)
- fpdf (optional PDF report generation)

## Vulnerability Detection Patterns

- Classic vulnerabilities: SQL Injection, XSS, Command Injection, etc.
- MCP-Specific vulnerabilities: Prompt Injection, Tool Misuse, Memory Poisoning, Credential Harvesting, Unauthenticated Proxy RCE, Privilege Escalation.
- AI/LLM vulnerabilities: Model Inversion, Data Poisoning.
- Supply chain and configuration issues.

## Example Output
```json
{
  "executive_summary": "Critical MCP vulnerabilities detected requiring immediate attention",
  "summary": {
    "critical": 2,
    "high": 5,
    "medium": 8,
    "low": 12,
    "total": 27,
    "repos_scanned": 3,
    "external_vulns": 15
  },
  "vulnerabilities": [
    {
      "type": "prompt_injection",
      "line": 45,
      "code": "prompt += user_input",
      "file": "src/agent.py",
      "pattern": "prompt\\s*\\+\\s*user_input"
    }
  ]
}
```

## Contributing

Contributions are welcome. See [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/DINAKAR-S/Agentic-MCP-Scanner.git
cd Agentic-MCP-Scanner
python -m venv venv
source venv/bin/activate  # On Windows use venv\Scripts\activate
pip install -r requirements.txt
```
### Attribution
Developed under academic research at **Amrita Vishwa Vidyapeetham, Coimbatore**. All rights reserved by the institution.

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Disclaimer

Use this tool for authorized security research and testing only.

## Support

- Issues: [GitHub Issues](https://github.com/DINAKAR-S/Agentic-MCP-Scanner/issues)
- Discussions: [GitHub Discussions](https://github.com/DINAKAR-S/Agentic-MCP-Scanner/discussions)

## Acknowledgments

- Agno (multi-agent framework)
- Firecrawl (threat intelligence)
- Google Generative AI (LLM capabilities)
- The MCP community for security research
