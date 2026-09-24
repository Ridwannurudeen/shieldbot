from pathlib import Path

from setuptools import setup, find_packages

setup(
    name="shieldbot",
    version="3.0.0",
    description="Async client for the ShieldBot agent transaction firewall, with a local verdict cache and explicit fail modes",
    long_description=Path(__file__).with_name("README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    author="ShieldBot Security",
    url="https://shieldbotsecurity.online",
    project_urls={
        "Source": "https://github.com/Ridwannurudeen/shieldbot/tree/main/sdk/python",
    },
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.9",
    install_requires=[
        "httpx>=0.24.0",
    ],
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
)
