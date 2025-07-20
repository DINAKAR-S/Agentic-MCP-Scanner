import os
from agno.agent import Agent
from agno.models.openai import OpenAIChat
from agno.tools.duckduckgo import DuckDuckGoTools
from agno.utils.log import logger
from firecrawl import FirecrawlApp

class FirecrawlIntegrationAgent(Agent):
    def __init__(self):
        super().__init__(
            name="Vulnerability Researcher",
            role="Search for recent security vulnerabilities",
            model=OpenAIChat(id="gpt-4o-mini"),
            tools=[DuckDuckGoTools()],
            instructions=[
                "Use Firecrawl API to search for security advisories",
                "Identify relevant CVEs and exploit patterns",
                "Cross-reference findings with code analysis"
            ]
        )

    def firecrawl_search_and_crawl(self, vuln_urls):
        api_key = os.environ.get("FIRECRAWL_API_KEY")
        if not api_key:
            logger.error("FIRECRAWL_API_KEY environment variable is not set. Skipping Firecrawl integration.")
            return []
        app = FirecrawlApp(api_key=api_key)
        results = []

        # Search for recent vulnerabilities
        search_result = app.search("AI MCP LLM vulnerability", limit=10)
        for r in search_result.data:
            results.append({
                "name": r.get("title", "Unknown"),
                "description": (r.get("description") or "")[:200],
                "source_url": r.get("url")
            })

        # Crawl specific URLs
        for url in vuln_urls:
            try:
                crawl_result = app.scrape_url(url, formats=['markdown', 'html'])
                results.append({
                    "name": getattr(crawl_result, "title", url),
                    "description": getattr(crawl_result, "description", ""),
                    "source_url": url
                })
            except Exception as e:
                results.append({
                    "name": f"Error crawling {url}",
                    "description": f"Failed to crawl {url}: {str(e)}",
                    "source_url": url
                })
        return results 