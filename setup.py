"""Setup script for Ghost SARIF converter."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="ghost-sarif",
    version="1.0.0",
    author="Ghost SARIF Client",
    description="API client to Ghost Application security platform that converts vulnerability findings to SARIF output",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ghostsecurity/ghost-sarif",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
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
            "ghost-sarif=ghost_sarif.cli:cli",
        ],
    },
    keywords="security, sarif, ghost, vulnerability, scanning, api",
    project_urls={
        "Bug Reports": "https://github.com/ghostsecurity/ghost-sarif/issues",
        "Source": "https://github.com/ghostsecurity/ghost-sarif",
        "Documentation": "https://docs.ghostsecurity.ai",
    },
)
