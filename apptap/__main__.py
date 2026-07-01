"""Allow running as: python -m apptap"""

import sys

from apptap.cli import main

if __name__ == "__main__":
    sys.exit(main())
