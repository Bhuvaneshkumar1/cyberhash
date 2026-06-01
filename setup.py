from setuptools import setup

setup(
    name="cyberhash",
    version="3.0",
    py_modules=["cyberhash"],
    install_requires=[
        "rich",
        "pyfiglet",
        "passlib",
        "pycryptodome",
        "crcmod"
    ],
    entry_points={
        "console_scripts": [
            "cyberhash=cyberhash:main"
        ]
    }
)