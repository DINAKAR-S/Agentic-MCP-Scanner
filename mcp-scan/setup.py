from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="mcpvuln",
    version="0.1.0",
    author="Dinakar S",
    author_email="dinakars2003@gmail.com",
    description="MCP Vulnerability Analysis & Monitoring Pipeline",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/DINAKAR-S/Agentic-MCP-Scanner/",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "mcpvuln=mcpvuln.cli:main",
        ],
    },
    keywords="security, vulnerability, analysis, mcp, model-context-protocol, ai, llm",
    project_urls={
        "Bug Reports": "https://github.com/DINAKAR-S/Agentic-MCP-Scanner/issues",
        "Source": "https://github.com/DINAKAR-S/Agentic-MCP-Scanner/",
    },
    include_package_data=True,
    zip_safe=False,
)
