#!/usr/bin/env python3
"""
Extract OpenHands version from Python source of truth
"""

import sys
import argparse
from pathlib import Path

# Add src directory to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))


def get_openhands_version(version_type="full"):
    """Extract OpenHands version from Python source of truth"""
    try:
        from dcypher.openhands_version import get_version, get_repo_version

        if version_type == "repo":
            return get_repo_version()
        else:  # default to "full" (now Docker-safe with commit info)
            return get_version()
    except ImportError as e:
        print(f"Error importing dcypher.openhands_version: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error getting OpenHands version: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Get OpenHands version")
    parser.add_argument(
        "--full",
        action="store_true",
        help="Return full version with commit info (e.g., '0.48.0-8937b3fbf') - DEFAULT",
    )
    parser.add_argument(
        "--repo",
        action="store_true",
        help="Return repo version only (e.g., '0.48.0')",
    )

    args = parser.parse_args()

    if args.repo:
        version_type = "repo"
    else:
        # Default to full version (now Docker-safe with commit info)
        version_type = "full"

    print(get_openhands_version(version_type))
