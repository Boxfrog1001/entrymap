from pathlib import Path
from setuptools import setup, find_packages

readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="entrymap",
    version="0.2.1",
    author="FrogSec",
    description="A fast, modular scanner and anomaly detection suite for Tor Entry Guards and HSDirs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Boxfrog1001/entrymap",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    scripts=["bin/entrymap"],
    install_requires=[
        "cryptography>=3.4.0",
        "requests>=2.25.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.8",
)
