from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="kharma-radar",
    version="10.0.2",
    author="Mutasem-mk4",
    author_email="example@example.com",
    description="The Over-Watch Network Monitor: An elite CLI tool mapping active connections to process IDs, geographical locations, and threat intelligence.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Mutasem-mk4/kharma-network-radar",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Environment :: Console",
    ],
    python_requires='>=3.8',
    install_requires=[
        'click',
        'rich',
        'psutil',
        'requests',
        'maxminddb',
        'vt-py',
        'rich-click',
        'Flask',
        'Flask-Cors',
        'scapy',
    ],
    project_urls={
        "Bug Tracker": "https://github.com/Mutaz/kharma-network-radar/issues",
        "Source Code": "https://github.com/Mutaz/kharma-network-radar",
        "Documentation": "https://github.com/Mutaz/kharma-network-radar#readme",
    },
    entry_points={
        "console_scripts": [
            "kharma=kharma.main:cli",
        ],
    },
)
