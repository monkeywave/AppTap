#!/usr/bin/env python3
import importlib.util
from pathlib import Path

from setuptools import find_packages, setup

# Paths
ROOT = Path(__file__).resolve().parent
PKG = "apptap"
ABOUT = ROOT / PKG / "about.py"
README = ROOT / "README.md"
REQUIREMENTS = ROOT / "requirements.txt"

# Load metadata from about.py safely (no import of the package itself)
spec = importlib.util.spec_from_file_location(f"{PKG}.about", ABOUT)
about = importlib.util.module_from_spec(spec)
spec.loader.exec_module(about)  # type: ignore[attr-defined]

# Long description
long_description = README.read_text(encoding="utf-8") if README.exists() else ""

# Runtime requirements (single source of truth: requirements.txt)
install_requires = [
    line.strip()
    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.startswith("#")
]

setup(
    name="AppTap",
    version=about.__version__,
    description=about.__description__,
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/monkeywave/AppTap",
    author=about.__author__,
    author_email="daniel.baier@fkie.fraunhofer.de",
    license="MIT",
    packages=find_packages(exclude=("tests",)),
    python_requires=">=3.8",
    install_requires=install_requires,
    # Bundle the arch-specific tcpdump binaries inside the package
    package_data={
        "apptap": [
            "assets/tcpdump_binaries/*",
        ],
    },
    include_package_data=True,
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Natural Language :: English",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    keywords=["pcap", "tcpdump", "android", "uid", "traffic", "capture", "netfilter", "nflog"],
    entry_points={
        "console_scripts": [
            "apptap=apptap.cli:main",
        ],
    },
    project_urls={
        "Source": "https://github.com/monkeywave/AppTap",
        "Issues": "https://github.com/monkeywave/AppTap/issues",
    },
)
