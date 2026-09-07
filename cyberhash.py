#!/usr/bin/env python3
"""
CyberHash backwards-compatibility entry point script.
Delegates execution to cyberhash.cli:main.
"""

import sys
from cyberhash.cli import main

if __name__ == "__main__":
    main()