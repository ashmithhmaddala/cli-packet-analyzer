#!/usr/bin/env python3

"""
Setup script for CLI Packet Analyzer - Kali Linux Edition
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="cli-pcap-analyzer",
    version="1.0.0",
    author="Ashmith Maddala",
    author_email="ashmithhmaddala@gmail.com",
    description="Advanced CLI packet analyzer for Kali Linux with protocol dissection and export capabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ashmithhmaddala/cli-packet-analyzer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Networking :: Analysis",
    ],
    python_requires=">=3.7",
    install_requires=[
        "scapy>=2.4.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "black",
            "flake8",
            "mypy",
        ],
        "performance": [
            "pyshark>=0.4.0",  # Alternative to scapy for performance
        ],
        "kali": [
            # Additional packages useful in Kali Linux environment
            "requests",  # For HTTP analysis
            "cryptography",  # For TLS analysis
        ],
    },
    entry_points={
        "console_scripts": [
            "pcap-analyzer=cli_pcap_analyzer.cli:main",
            "packet-analyzer=cli_pcap_analyzer.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords=[
        "packet-analyzer",
        "network-analysis",
        "pcap",
        "kali-linux",
        "security-tools",
        "networking",
        "protocol-dissection",
    ],
)
