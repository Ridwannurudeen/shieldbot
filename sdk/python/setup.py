from setuptools import setup, find_packages

setup(
    name="shieldbot",
    version="0.1.0",
    description="ShieldBot SDK — AI agent transaction firewall for BNB Chain",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "httpx>=0.24.0",
    ],
)
