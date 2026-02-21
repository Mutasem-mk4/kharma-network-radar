from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="kharma-radar",
    version="4.0.1",
    author="Mutasem (@Mutasem-mk4)",
    author_email="example@example.com",
    description="The Over-Watch Network Monitor: An elite CLI tool mapping active connections to process IDs, geographical locations, and threat intelligence.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Mutaz/kharma-network-radar",
    packages=find_packages(),
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
    ],
    entry_points={
        "console_scripts": [
            "kharma=kharma.main:cli",
        ],
    },
)
