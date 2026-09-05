"""
Main entrypoint when invoking module via `python -m erasure`.
"""

import sys
from erasure.cli import main

if __name__ == "__main__":
    sys.exit(main())
