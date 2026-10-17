"""Setup script for The Red Room."""

from setuptools import setup, find_packages

setup(
    name="red-room",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "fastapi>=0.110.0",
        "uvicorn>=0.27.0",
        "pydantic>=2.6.0",
        "structlog>=24.1.0",
        "rich>=13.7.0",
        "typer>=0.9.0",
        "httpx>=0.27.0",
        "pyyaml>=6.0",
    ],
    python_requires=">=3.10",
)
