"""Allow `python3 -m netlab`."""

from netlab.app import main

if __name__ == "__main__":
    raise SystemExit(main())
