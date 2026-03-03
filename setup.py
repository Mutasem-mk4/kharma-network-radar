from setuptools import setup, find_packages
import os

def read_requirements():
    if os.path.exists("requirements.txt"):
        with open("requirements.txt") as f:
            return f.read().splitlines()
    return ["flask", "psutil", "requests", "pyjwt", "cryptography", "reportlab"]

setup(
    name="kharma-sentinel",
    version="1.0.0",
    author="Mutasem",
    description="Advanced Offensive Intelligence & Real-Time Active Defense Suite",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Mutasem-mk4/kharma-network-radar",
    packages=find_packages(),
    include_package_data=True,
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "kharma=kharma.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
)
