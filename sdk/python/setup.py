from setuptools import setup, find_packages

setup(
    name="shieldbot",
    version="3.0.0",
    description="ShieldBot V3 SDK — agent transaction firewall, threat intelligence, reputation scoring, and prompt injection detection",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="ShieldBot Security",
    url="https://shieldbotsecurity.online",
    project_urls={
        "Source": "https://github.com/Ridwannurudeen/shieldbot/tree/main/sdk/python",
    },
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "httpx>=0.24.0",
    ],
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
)
