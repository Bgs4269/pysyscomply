"""Compatibility launcher for the pysyscomply package."""

from pysyscomply import *
from pysyscomply import __version__, main


if __name__ == "__main__":
    raise SystemExit(main())
