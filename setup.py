"""Setup script for cryptoluggage
"""

import os.path
from setuptools import setup

# The directory containing this file
HERE = os.path.abspath(os.path.dirname(__file__))

# The text of the README file
with open(os.path.join(HERE, "README.md")) as fid:
    README = fid.read()

# This call to setup() does all the work
setup(
    name="cryptoluggage",
    version="3.0.3",
    description="Cryptoluggage allows to keep encrypted secrets (e.g., passwords) and files",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/miguelinux314/cryptoluggage",
    author="Miguel Hernández Cabronero",
    author_email="miguel.hernandez@uab.cat",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    packages=["cryptoluggage"],
    include_package_data=True,
    python_requires='>=3.6',
    install_requires=["cryptography", "filelock", "sortedcontainers", "prompt_toolkit"],
    entry_points={"console_scripts": ["cl=cryptoluggage.__main__:__main__"]},
)
