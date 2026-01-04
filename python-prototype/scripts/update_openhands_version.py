#!/usr/bin/env python3
"""
Update OpenHands version and commit SHA in the Python source of truth

Usage:
    python scripts/update_openhands_version.py --version 0.49.2 --sha abc123456
    python scripts/update_openhands_version.py --auto  # Use current vendored repo state
"""

import sys
import argparse
import subprocess
from pathlib import Path


def get_current_vendored_commit():
    """Get the current commit from the vendored OpenHands repo"""
    try:
        # Get short SHA
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd="vendor/openhands",
            capture_output=True,
            text=True,
            check=True,
        )
        short_sha = result.stdout.strip()

        # Get full SHA
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd="vendor/openhands",
            capture_output=True,
            text=True,
            check=True,
        )
        full_sha = result.stdout.strip()

        return short_sha, full_sha
    except subprocess.CalledProcessError as e:
        print(f"Error getting vendored commit: {e}", file=sys.stderr)
        sys.exit(1)


def update_version_file(short_sha, full_sha):
    """Update the OpenHands version file with new commit values"""
    version_file = Path("src/dcypher/openhands_version.py")

    if not version_file.exists():
        print(f"Error: {version_file} not found", file=sys.stderr)
        sys.exit(1)

    # Read current content
    content = version_file.read_text()

    # Update the values
    lines = content.split("\n")
    for i, line in enumerate(lines):
        if line.startswith("OPENHANDS_COMMIT_SHA = "):
            lines[i] = (
                f'OPENHANDS_COMMIT_SHA = "{short_sha}"  # Current vendored commit'
            )
        elif line.startswith("OPENHANDS_FULL_SHA = "):
            lines[i] = f'OPENHANDS_FULL_SHA = "{full_sha}"'

    # Write updated content
    version_file.write_text("\n".join(lines))
    print(f"✅ Updated {version_file}")
    print(f"   Short SHA: {short_sha}")
    print(f"   Full SHA: {full_sha}")


def main():
    parser = argparse.ArgumentParser(
        description="Update OpenHands version and commit SHA"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--auto", action="store_true", help="Use current vendored repo state"
    )
    group.add_argument("--version", help="OpenHands version")
    group.add_argument("--commit", help="Commit SHA to update to")

    parser.add_argument("--sha", help="Commit SHA (required with --version)")
    parser.add_argument("--full-sha", help="Full commit SHA (for --commit option)")

    args = parser.parse_args()

    if args.auto:
        # Use current vendored repo
        short_sha, full_sha = get_current_vendored_commit()
        # TODO: Extract version from vendored repo if needed
        version = "0.49.1"  # Default for now
        print(f"Using current vendored repo state:")
        update_version_file(short_sha, full_sha)
    elif args.version:
        if not args.sha:
            print("Error: --sha is required when using --version", file=sys.stderr)
            sys.exit(1)
        version = args.version
        short_sha = args.sha
        full_sha = args.sha  # Assume it's already full SHA or extend as needed
        print(f"Using provided values:")
        update_version_file(short_sha, full_sha)
    elif args.commit:
        short_sha = args.commit
        full_sha = args.full_sha if args.full_sha else args.commit
        print(f"Updating to commit {short_sha}:")
        update_version_file(short_sha, full_sha)


if __name__ == "__main__":
    main()
