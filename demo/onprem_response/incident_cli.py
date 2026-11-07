"""Owner terminal controls for finite incident qualification."""

import argparse
import json
from pathlib import Path

from .terminal_cli import submit


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("action", choices=["attempt", "status", "stop"])
    a = p.parse_args()
    try:
        print(json.dumps(submit(a.state, a.action), ensure_ascii=False, indent=2))
    except ValueError as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
