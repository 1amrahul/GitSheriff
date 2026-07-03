from setuptools import setup, find_packages

setup(
    name="gitsheriff",
    version="2.0.0",
    author="Rahul",
    author_email="rahul@rahulms.qzz.io",
    description="A .git exposure detection, dumping, recovery, and sensitive data scanning toolkit",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/1amrahul/GitSheriff",
    project_urls={
        "Website": "https://rahulms.qzz.io",
        "Bug Tracker": "https://github.com/1amrahul/GitSheriff/issues",
    },
    packages=find_packages(),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "gitsheriff=gitsheriff.cli:main",
        ],
    },
    license_file="LICENSE",
    keywords=[
        "git", "security", "exposure", "bug-bounty", "penetration-testing",
        "recon", "osint", "sensitive-data", "secret-scanning", "dotenv",
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
)
