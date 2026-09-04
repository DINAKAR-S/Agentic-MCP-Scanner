from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Core install stays deliberately small: detection, scoring and reporting run with
# no network access and no API key. Everything else is an extra.
CORE = ["cvss==3.6"]

EXTRAS = {
    "github": ["gitingest==0.1.4"],
    "narrative": ["google-generativeai==0.8.5", "python-dotenv==1.1.1"],
    "intel": ["firecrawl-py==2.16.3", "python-dotenv==1.1.1"],
    "dev": ["pytest==8.4.2", "pytest-cov==6.2.1", "ruff==0.13.0"],
}
EXTRAS["all"] = sorted({d for k, v in EXTRAS.items() if k != "dev" for d in v})

setup(
    name="mcpvuln",
    version="0.2.0",
    author="Dinakar S",
    author_email="dinakars2003@gmail.com",
    description="Vulnerability detection for Model Context Protocol codebases, with a reproducible benchmark",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/DINAKAR-S/Agentic-MCP-Scanner/",
    packages=find_packages(exclude=["tests", "tests.*", "benchmark", "benchmark.*"]),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    python_requires=">=3.9",
    install_requires=CORE,
    extras_require=EXTRAS,
    entry_points={"console_scripts": ["mcpvuln=mcpvuln.cli:main"]},
    keywords="security, vulnerability, analysis, mcp, model-context-protocol, ai, llm, benchmark",
    project_urls={
        "Bug Reports": "https://github.com/DINAKAR-S/Agentic-MCP-Scanner/issues",
        "Source": "https://github.com/DINAKAR-S/Agentic-MCP-Scanner/",
    },
    include_package_data=True,
    zip_safe=False,
)
