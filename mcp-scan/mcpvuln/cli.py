import os
import sys
import logging
from mcpvuln.team import SecurityAnalysisTeam
from dotenv import load_dotenv
from colorama import init, Fore, Style
from time import sleep
from tqdm import tqdm

def animated_welcome():
    init(autoreset=True)
    banner = [
        f"{Fore.CYAN}{Style.BRIGHT}███╗   ███╗ ██████╗ ██████╗ ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗",
        f"{Fore.CYAN}{Style.BRIGHT}████╗ ████║██╔═══██╗██╔══██╗██║   ██║██║   ██║██║     ████╗  ██║",
        f"{Fore.CYAN}{Style.BRIGHT}██╔████╔██║██║   ██║██████╔╝██║   ██║██║   ██║██║     ██╔██╗ ██║",
        f"{Fore.CYAN}{Style.BRIGHT}██║╚██╔╝██║██║   ██║██╔══██╗██║   ██║██║   ██║██║     ██║╚██╗██║",
        f"{Fore.CYAN}{Style.BRIGHT}██║ ╚═╝ ██║╚██████╔╝██║  ██║╚██████╔╝╚██████╔╝███████╗██║ ╚████║",
        f"{Fore.CYAN}{Style.BRIGHT}╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝",
        f"{Fore.YELLOW}MCP Vulnerability Analysis & Monitoring Pipeline\n"
    ]
    for line in banner:
        print(line)
        sleep(0.1)
    for _ in tqdm(range(30), desc=f"{Fore.GREEN}Initializing", ncols=70, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}'):
        sleep(0.02)
    print(f"{Fore.MAGENTA}{Style.BRIGHT}Ready to scan!\n")

def main():
    load_dotenv()
    animated_welcome()
    missing_keys = []
    if not os.environ.get("GOOGLE_API_KEY"):
        missing_keys.append("GOOGLE_API_KEY")
    if not os.environ.get("FIRECRAWL_API_KEY"):
        print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} FIRECRAWL_API_KEY not set. Firecrawl integration will be skipped.")
    if missing_keys:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Missing required environment variables: {', '.join(missing_keys)}")
        print(f"Please add them to a .env file in your project directory.")
        print(f"Example .env file:\nGOOGLE_API_KEY=your_google_api_key\nFIRECRAWL_API_KEY=your_firecrawl_api_key")
        exit(1)

    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
    if len(sys.argv) < 2:
        print(f"{Fore.YELLOW}Usage: mcpvuln <github_repo_url1> [<github_repo_url2> ...]{Style.RESET_ALL}")
        print("Example: mcpvuln https://github.com/user/repo1 https://github.com/user/repo2")
        exit(0)
    github_urls = sys.argv[1:]
    vuln_urls = [
        "https://github.com/accuknox/agentic-ai-strands",
        "https://aws.amazon.com/blogs/machine-learning/protect-sensitive-data-in-rag-applications-with-amazon-bedrock/",
        "https://github.com/invariantlabs-ai/mcp-scan",
        "https://blog.virustotal.com/2025/06/what-17845-github-repos-taught-us-about.html",
        "https://unit42.paloaltonetworks.com/agentic-ai-threats/",
        "https://invariantlabs.ai/blog/whatsapp-mcp-exploited",
        "https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe",
        "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",
        "https://www.tensorzero.com/blog/reverse-engineering-cursors-llm-client/",
        "https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/",
        "https://gbhackers.com/threat-actors-manipulate-search-results/",
        "https://blog.bsidesmumbai.in/posts/aipowered-attack/",
        "https://github.com/Tomby68/mcp-vulnerabilities",
        "https://vulnerablemcp.info/index.html",
        "https://hiddenlayer.com/innovation-hub/exploiting-mcp-tool-parameters/",
        "https://strobes.co/blog/mcp-model-context-protocol-and-its-critical-vulnerabilities/",
        "https://gbhackers.com/anthropic-mcp-inspector-vulnerability/",
        "https://cybersecuritynews.com/anthropic-mcp-inspector-vulnerability/",
        "https://www.backslash.security/blog/hundreds-of-mcp-servers-vulnerable-to-abuse",
        "https://www.redhat.com/en/blog/model-context-protocol-mcp-understanding-security-risks-and-controls",
        "https://elenacross7.medium.com/%EF%B8%8F-the-s-in-mcp-stands-for-security-91407b33ed6b"
    ]
    security_team = SecurityAnalysisTeam()
    result = security_team.run_analysis(github_urls, vuln_urls)
    if isinstance(result["reports"], dict):
        for repo_url, md_path in result["reports"].items():
            print(f"\nMarkdown Report Generated for {repo_url}: {md_path}")
    else:
        print("\nMarkdown Report Generated:", result["reports"])
    print("\nExternal Vulnerabilities Markdown Generated:", result["external_vuln_md"])
    if isinstance(result["vulnerabilities"], dict):
        print("\nVulnerabilities Found:", sum(len(v) for v in result["vulnerabilities"].values()))
    else:
        print("\nVulnerabilities Found: 0 (error in analysis)")
    if isinstance(result["external_vulns"], list):
        print("\nExternal Vulnerability Sources:", len(result["external_vulns"]))
    else:
        print("\nExternal Vulnerability Sources: 0 (error in analysis)")
    print(f"\n{Fore.GREEN}[INFO]{Style.RESET_ALL} All outputs are ready for security, engineering, and business review. See the markdown files for details.")

if __name__ == "__main__":
    main() 