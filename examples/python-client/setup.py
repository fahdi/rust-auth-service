"""Setup script for the Rust Auth Service Python client."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="rust-auth-client",
    version="1.0.0",
    author="Rust Auth Service Team",
    author_email="support@example.com",
    description="Python client library for the Rust Auth Service",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fahdi/rust-auth-service",
    project_urls={
        "Bug Tracker": "https://github.com/fahdi/rust-auth-service/issues",
        "Documentation": "https://github.com/fahdi/rust-auth-service/docs",
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
        "urllib3>=1.26.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.10",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.812",
            "requests-mock>=1.8",
        ],
        "docs": [
            "sphinx>=4.0",
            "sphinx-rtd-theme>=0.5",
        ],
    },
    entry_points={
        "console_scripts": [
            "rust-auth-demo=rust_auth_client.demo:main",
        ],
    },
    keywords="authentication auth jwt api client rust",
    include_package_data=True,
    zip_safe=False,
)