#!/usr/bin/env python3
"""
Extract OpenHands commit SHA from Python source of truth
"""

import sys
from pathlib import Path

# Add src directory to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))


def get_openhands_sha():
    """Extract OpenHands commit SHA from Python source of truth"""
    try:
        from dcypher.openhands_version import get_commit_sha

        return get_commit_sha()
    except ImportError as e:
        print(f"Error importing dcypher.openhands_version: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error getting OpenHands SHA: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    print(get_openhands_sha())
