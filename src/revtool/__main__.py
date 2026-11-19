"""Allow running via `python -m revtool`."""

import sys
from revtool.cli import main

if __name__ == "__main__":
    sys.exit(main())
