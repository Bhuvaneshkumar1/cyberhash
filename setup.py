from setuptools import setup

setup(
name="cyberhash",
version="1.0",
py_modules=["cyberhash"],
install_requires=[
"rich",
"pyfiglet"
],
entry_points={
"console_scripts": [
"cyberhash=cyberhash:main"
]
}
)
