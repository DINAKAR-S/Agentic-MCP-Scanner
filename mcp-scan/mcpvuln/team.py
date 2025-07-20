import logging
from agno.models.openai import OpenAIChat
from agno.team.team import Team
from .github_scraper import GitHubScraperAgent
from .vuln_analyzer import VulnerabilityAnalysisAgent
from .firecrawl_integration import FirecrawlIntegrationAgent
from .report_generator import ReportGeneratorAgent

class SecurityAnalysisTeam(Team):
    def __init__(self):
        super().__init__(
            name="Security Analysis Team",
            mode="coordinate",
            model=OpenAIChat(id="gpt-4o-mini"),
            members=[
                GitHubScraperAgent(),
                VulnerabilityAnalysisAgent(),
                FirecrawlIntegrationAgent(),
                ReportGeneratorAgent()
            ],
            instructions=[
                "1. Firecrawl search & blog/news extraction",
                "2. Vulnerability analysis of GitHub MCP codebases via multi-agents",
                "3. LLM-enriched reporting (CVSS, nutrition matrix, SSVC risk/action guidance)",
                "4. Output ready for security, engineering, or leadership stakeholders"
            ],
            markdown=True,
            show_members_responses=True,
            enable_agentic_context=True
        )

    def run_analysis(self, github_urls, vuln_urls, include_patterns=None, exclude_patterns=None, max_file_size=None, token=None):
        logging.info("[Stage 1] Firecrawl search & blog/news extraction...")
        github_scraper = self.members[0]
        vuln_analyzer = self.members[1]
        firecrawl_agent = self.members[2]
        report_generator = self.members[3]

        vuln_urls_to_crawl = vuln_urls[:10]
        vuln_info = firecrawl_agent.firecrawl_search_and_crawl(vuln_urls_to_crawl)
        external_vuln_path = "external_vulnerabilities.md"
        with open(external_vuln_path, "w", encoding="utf-8") as f:
            for v in vuln_info:
                f.write(f"### {v.get('name', 'Unknown')}\n")
                f.write(f"- **Description:** {v.get('description', '')}\n")
                f.write(f"- **Source:** {v.get('source_url', '')}\n\n")
        logging.info(f"Saved Firecrawl findings to {external_vuln_path}")

        repo_data = github_scraper.scrape_github_repos(
            github_urls,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
            max_file_size=max_file_size,
            token=token
        )
        all_repo_data = {}
        for repo in repo_data:
            findings = []
            for file_path, content in repo['files'].items():
                findings.extend(vuln_analyzer.analyze(content, file_path))
            all_repo_data[repo['url']] = findings
        logging.info("Aggregated all codebase findings.")

        report_paths = {}
        for repo_url, findings in all_repo_data.items():
            repo_name = repo_url.rstrip('/').split('/')[-1]
            md_path = f"{repo_name}_security_report.md"
            report_text = report_generator.generate_gemini_cvss_nutrition_report({repo_url: findings}, external_vulns=vuln_info)
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(report_text)
            with open(md_path, "a", encoding="utf-8") as f:
                f.write("\n---\n")
                f.write(f"## External Vulnerabilities\n")
                f.write(f"See [external_vulnerabilities.md](external_vulnerabilities.md) for details on {len(vuln_info)} real-time vulnerabilities found via Firecrawl.\n")
            report_paths[repo_url] = md_path
        logging.info(f"Saved markdown reports: {list(report_paths.values())}")

        return {
            "reports": report_paths,
            "external_vuln_md": external_vuln_path,
            "vulnerabilities": all_repo_data,
            "external_vulns": vuln_info
        } 