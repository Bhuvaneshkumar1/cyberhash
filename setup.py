from setuptools import setup, find_packages

setup(
    name="cyberhash",
    version="3.0",
    packages=find_packages(),
    py_modules=["cyberhash"],
    install_requires=[
        "rich",
        "pyfiglet",
        "passlib"
    ],
    entry_points={
        "console_scripts": [
            "cyberhash=cyberhash.cli:main"
        ]
    }
)