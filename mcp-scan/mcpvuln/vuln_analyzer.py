import re
from agno.agent import Agent
from agno.models.openai import OpenAIChat

VULN_DESCRIPTIONS = {
    'sql_injection': "SQL Injection: Unsanitized user input in database queries can allow attackers to execute malicious SQL.",
    'command_injection': "Command Injection: User input is used in system commands, leading to possible remote code execution.",
    'xss': "Cross-Site Scripting (XSS): User input is inserted into web pages, enabling attackers to run scripts in users' browsers.",
    'path_traversal': "Path Traversal: User input allows access to files outside the intended directory.",
    'hardcoded_secrets': "Hardcoded Secrets: Sensitive credentials are stored directly in code.",
    'insecure_random': "Insecure Random: Weak random number generators used for security-sensitive operations.",
    'weak_crypto': "Weak Cryptography: Use of outdated or insecure cryptographic algorithms.",
    'mcp_request': "MCP Request: Usage of Model Context Protocol functions, which may introduce agentic risks.",
    'prompt_injection': "Prompt Injection: User input is used directly in prompts, potentially manipulating LLM behavior.",
    'tool_misuse': "Tool Misuse: Insecure or unintended use of system tools by the AI agent.",
    'overbroad_permissions': "Overbroad Permissions: Code grants excessive access rights or permissions.",
    'credential_harvesting': "Credential Harvesting: Code collects or transmits sensitive credentials.",
    'memory_poisoning': "Memory Poisoning: Manipulation of agent memory or context to alter behavior.",
    'novel_vulnerability': "Novel Vulnerability: Suspicious use of eval/exec not covered by known patterns.",
    'data_poisoning': "Data Poisoning: Malicious manipulation of training or context data to subvert AI behavior.",
    'model_inversion': "Model Inversion: Attempts to extract sensitive data from model outputs.",
    'unauthenticated_proxy_rce': "Unauthenticated Proxy RCE: Remote code execution via unauthenticated or misconfigured MCP proxy.",
    'token_theft': "Token Theft: Leakage or theft of authentication tokens.",
    'privilege_escalation': "Privilege Escalation: Gaining higher privileges via misconfiguration or agent abuse.",
    'misconfiguration': "Misconfiguration: Dangerous settings or policy drift.",
    'malicious_package': "Malicious Package: Supply chain/package attack via untrusted dependencies.",
    'prompt_tool_abuse': "Prompt Tool Abuse: Prompt-based abuse of tools.",
    'file_encryption': "File Encryption: File encryption or ransomware behavior.",
    'unsafe_file_access': "Unsafe File Access: Insecure file read/write/delete.",
    'insecure_http': "Insecure HTTP: Use of HTTP instead of HTTPS (MITM risk).",
    'policy_drift': "Policy Drift: Excessive permissions or policy misalignment.",
}

class VulnerabilityAnalysisAgent(Agent):
    def __init__(self):
        super().__init__(
            name="Vulnerability Analyzer",
            role="Detect security vulnerabilities in code",
            model=OpenAIChat(id="gpt-4o-mini"),
            tools=[],
            instructions=[
                "Use regex patterns to detect security issues",
                "Identify both classic and MCP-specific vulnerabilities",
                "Prioritize findings using SSVC framework"
            ]
        )
        self.patterns = {
            'sql_injection': [
                r'execute\s*\(\s*["\'].*%.*["\']',
                r'query\s*\(\s*["\'].*\+.*["\']',
                r'cursor\.execute\s*\(\s*["\'].*%.*["\']'
            ],
            'xss': [
                r'innerHTML\s*=\s*.*\+',
                r'document\.write\s*\(\s*.*\+',
                r'eval\s*\(\s*.*input'
            ],
            'command_injection': [
                r'os\.system\s*\(\s*.*\+',
                r'subprocess\.\w+\s*\(\s*.*\+',
                r'exec\s*\(\s*.*input'
            ],
            'path_traversal': [
                r'open\s*\(\s*.*\+.*["\']\.\./',
                r'file\s*\(\s*.*\+.*["\']\.\./',
                r'readFile\s*\(\s*.*\+.*["\']\.\./'
            ],
            'hardcoded_secrets': [
                r'password\s*=\s*["\'][^"\']{8,}["\']',
                r'api_key\s*=\s*["\'][^"\']{20,}["\']',
                r'secret\s*=\s*["\'][^"\']{16,}["\']'
            ],
            'insecure_random': [
                r'random\.random\(\)',
                r'Math\.random\(\)',
                r'rand\(\)'
            ],
            'weak_crypto': [
                r'md5\s*\(',
                r'sha1\s*\(',
                r'DES\s*\('
            ],
            'mcp_request': [
                r'mcp\.request\s*\(',
                r'mcp_server',
                r'mcp\.context'
            ],
            'prompt_injection': [
                r'prompt\s*\+\s*user_input',
                r'system_message.*\{.*user',
                r'openai\..*\(\s*.*user_controlled',
                r'zero-width-char',
                r'<!--.*-->',
            ],
            'tool_misuse': [
                r'subprocess\.\w+\s*\(\s*.*llm.*',
                r'os\.system\s*\(\s*.*llm.*',
                r'exec\s*\(\s*.*llm.*',
            ],
            'overbroad_permissions': [
                r'oauth.*\*',
                r'full_access',
                r'admin_access',
            ],
            'credential_harvesting': [
                r'os\.environ\[".*KEY.*"\]',
                r'os\.environ\[".*SECRET.*"\]',
                r'requests\.post\(.+\/secrets?',
            ],
            'memory_poisoning': [
                r'agent_memory\.store\(',
                r'context\.update\(',
            ],
            'malicious_server_supply_chain': [
                r'pip install .*://',
                r'curl .* | bash',
                r'wget .* | sh',
                r'latest',
            ],
            'rogue_server_impersonation': [
                r'http://',
                r'https?://[a-z0-9\-]*mcp.*\.[a-z]+',
                r'no_tls',
                r'hardcoded_ip',
            ],
            'credential_harvesting': [
                r'os\.environ\[".*KEY.*"\]',
                r'os\.environ\[".*SECRET.*"\]',
                r'requests\.post\(.+\/secrets?',
                r'read.*keychain',
            ],
            'tool_based_rce': [
                r'subprocess\.\w+\s*\(\s*.*input',
                r'os\.system\s*\(\s*.*input',
                r'exec\s*\(\s*.*input',
                r'rm -rf',
            ],
            'semantic_gap_poisoning': [
                r'manifest.*read-only',
                r'open\(',
                r'socket\.socket\(',
            ],
            'overbroad_permissions': [
                r'oauth.*\*',
                r'full_access',
                r'admin_access',
            ],
            'indirect_prompt_injection': [
                r'<!--.*-->',
                r'zero-width-char',
                r'base64.b64decode',
            ],
            'context_data_poisoning': [
                r'context\s*=\s*scrape\(',
                r'context\s*=\s*requests\.get',
            ],
            'sampling_feature_abuse': [
                r'completion_length\s*=\s*10000',
                r'prompt_leak',
            ],
            'living_off_the_land': [
                r'os\.system\("ls"\)',
                r'subprocess\.call\("whoami"\)',
            ],
            'chained_mcp_exploitation': [
                r'output\s*=\s*serverA\(',
                r'params\s*=\s*output',
            ],
            'financial_fraud_dos_persistence': [
                r'payment_api',
                r'infinite_loop',
                r'hot_swap_binary',
            ],
            'memory_poisoning': [
                r'agent_memory\.store\(',
                r'context\.update\(',
            ],
            'tool_misuse': [
                r'subprocess\.\w+\s*\(\s*.*llm.*',
                r'os\.system\s*\(\s*.*llm.*',
                r'exec\s*\(\s*.*llm.*',
            ],
            'privilege_compromise': [
                r'permission\s*=\s*None',
                r'role\s*=\s*dynamic',
            ],
            'resource_overload': [
                r'while\s+True',
                r'for\s+_+in\s+range\(1000000\)',
            ],
            'human_manipulation': [
                r'output\s*=\s*social_engineer',
            ],
            'cascading_hallucination': [
                r'self_reinforce',
                r'inter_agent_communication',
            ],
            'authentication_identity_abuse': [
                r'impersonate_user',
                r'bypass_auth',
            ],
            'multi_agent_poisoning': [
                r'trust\s*=\s*True',
                r'agent_communication',
            ]
        }

    def analyze(self, code_content, file_path):
        vulnerabilities = []
        lines = code_content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for vuln_type, patterns in self.patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': vuln_type,
                            'line': line_num,
                            'code': line.strip(),
                            'file': file_path,
                            'pattern': pattern
                        })
        return vulnerabilities 