import re
from agno.agent import Agent
from agno.models.openai import OpenAIChat
from agno.tools.duckduckgo import DuckDuckGoTools
from agno.utils.log import logger
import gitingest
from gitingest import ingest

class GitHubScraperAgent(Agent):
    def __init__(self):
        super().__init__(
            name="GitHub Scraper",
            role="Clone and analyze GitHub repositories",
            model=OpenAIChat(id="gpt-4o-mini"),
            tools=[DuckDuckGoTools()],
            instructions=[
                "Use gitingest to clone repositories",
                "Handle authentication for private repos",
                "Extract code content and metadata"
            ]
        )

    def parse_gitingest_content(self, content: str):
        file_blocks = re.split(r"=+\nFILE: (.+?)\n=+\n", content)
        repo_files = {}
        for i in range(1, len(file_blocks), 2):
            file_path = file_blocks[i].strip()
            file_content = file_blocks[i+1]
            repo_files[file_path] = file_content.strip()
        return repo_files

    def scrape_github_repos(self, github_urls, include_patterns=None, exclude_patterns=None, max_file_size=None, token=None):
        results = []
        for url in github_urls:
            try:
                ingest_kwargs = {}
                if include_patterns is not None:
                    ingest_kwargs['include_patterns'] = include_patterns
                if exclude_patterns is not None:
                    ingest_kwargs['exclude_patterns'] = exclude_patterns
                if max_file_size is not None:
                    ingest_kwargs['max_file_size'] = max_file_size
                if token is not None:
                    ingest_kwargs['token'] = token
                summary, tree, content = ingest(url, **ingest_kwargs)
                repo_files = self.parse_gitingest_content(content)
                results.append({
                    'url': url,
                    'summary': summary,
                    'tree': tree,
                    'files': repo_files
                })
            except Exception as e:
                logger.error(f"Failed to ingest {url}: {e}")
        return results 