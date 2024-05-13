# read the contents of your README file
from pathlib import Path

from setuptools import find_packages, setup  # type: ignore

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()


VERSION = "1.0.5"

setup(
    name="cloudgrep",
    version=VERSION,
    description="cloudgrep searches cloud storage",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Cado Security",
    author_email="cloudgrep@cadosecurity.com",
    url="https://github.com/cado-security/cloudgrep",
    download_url="https://github.com/cado-security/cloudgrep/archive/refs/heads/main.zip",
    py_modules=["cloudgrep"],
    install_requires=[
        "botocor",
        "boto3",
        "python-dateutil",
        "azure-storage-blob",
        "azure-core",
        "azure-identity",
        "google-cloud-storage",
        "yara-python-wheel",
    ],
    packages=find_packages(),
)
