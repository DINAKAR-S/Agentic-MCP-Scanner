import os

from setuptools import find_packages, setup

# The README lives at the repository root, one level above this file, and pip
# runs setup.py with an unpredictable working directory. Resolve it relative to
# this file and degrade gracefully if it is missing, rather than failing the
# install with a FileNotFoundError.
_HERE = os.path.dirname(os.path.abspath(__file__))
_DESCRIPTION = ("Vulnerability detection for Model Context Protocol codebases, "
                "with a reproducible benchmark")


def _long_description() -> str:
    """The PyPI page body.

    mcp-scan/README.md is written for PyPI: absolute links, since relative ones do
    not resolve there, and no repository-only sections. It ships in the sdist, which
    matters because `python -m build` builds the wheel from the sdist, so a README
    kept only at the repository root is not present at wheel-build time and the
    description silently degrades to the one-line summary.
    """
    for candidate in (os.path.join(_HERE, "README.md"),
                      os.path.join(os.path.dirname(_HERE), "README.md")):
        try:
            with open(candidate, encoding="utf-8") as fh:
                text = fh.read()
            if len(text) > 500:          # a real page, not a stub
                return text
        except OSError:
            continue
    return _DESCRIPTION


long_description = _long_description()

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
    version="0.2.1",
    author="Dinakar S",
    author_email="dinakars2003@gmail.com",
    description=_DESCRIPTION,
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
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
        "Environment :: Console",
        "Natural Language :: English",
        "Typing :: Typed",
    ],
    python_requires=">=3.9",
    install_requires=CORE,
    extras_require=EXTRAS,
    entry_points={"console_scripts": ["mcpvuln=mcpvuln.cli:main"]},
    keywords="security, vulnerability, analysis, mcp, model-context-protocol, ai, llm, benchmark",
    project_urls={
        "Homepage": "https://github.com/DINAKAR-S/Agentic-MCP-Scanner",
        "Source": "https://github.com/DINAKAR-S/Agentic-MCP-Scanner",
        "Issues": "https://github.com/DINAKAR-S/Agentic-MCP-Scanner/issues",
        "Changelog": "https://github.com/DINAKAR-S/Agentic-MCP-Scanner/blob/main/CHANGELOG.md",
        "Benchmark": "https://github.com/DINAKAR-S/Agentic-MCP-Scanner/tree/main/mcp-scan/benchmark",
        "Contributing": "https://github.com/DINAKAR-S/Agentic-MCP-Scanner/blob/main/CONTRIBUTING.md",
        "Security Policy": "https://github.com/DINAKAR-S/Agentic-MCP-Scanner/blob/main/SECURITY.md",
        "Release Notes": "https://github.com/DINAKAR-S/Agentic-MCP-Scanner/releases",
    },
    include_package_data=True,
    zip_safe=False,
)
