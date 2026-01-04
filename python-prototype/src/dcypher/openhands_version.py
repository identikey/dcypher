"""
OpenHands Version Configuration

This module defines the exact version and commit SHA for OpenHands that DCypher builds against.
This is the single source of truth for OpenHands versioning in the build system.

The version system automatically detects:
- Official release versions (from tags)
- Post-release commits (commit-based versioning)
- Pre-release commits (between releases)
"""

import subprocess
import os
from pathlib import Path


# Full commit SHA (for reference and verification)
OPENHANDS_FULL_SHA = "6b938527516ca4203fcbce6e61fa82af74528994"

# Exact commit SHA to check out and build from
# This ensures reproducible builds regardless of what's currently checked out
OPENHANDS_COMMIT_SHA = OPENHANDS_FULL_SHA[:9]  # Current vendored commit


def _get_repo_version_at_commit():
    """Get the actual version from the OpenHands repo at the specified commit"""
    try:
        repo_path = Path(__file__).parent.parent.parent / "vendor" / "openhands"
        if not repo_path.exists():
            return "0.48.0"  # Fallback

        # Read version from pyproject.toml at the specified commit
        result = subprocess.run(
            ["git", "show", f"{OPENHANDS_COMMIT_SHA}:pyproject.toml"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )

        for line in result.stdout.split("\n"):
            if line.strip().startswith("version = "):
                # Extract version from: version = "0.48.0"
                version = line.split("=")[1].strip().strip('"').strip("'")
                return version

        return "0.48.0"  # Fallback
    except:
        return "0.48.0"  # Fallback


def get_version() -> str:
    """Get the accurate OpenHands version string for this commit."""
    try:
        repo_path = Path(__file__).parent.parent.parent / "vendor" / "openhands"
        if not repo_path.exists():
            return f"0.48.0-{OPENHANDS_COMMIT_SHA}"

        # Check if our commit is exactly at a tag
        result = subprocess.run(
            ["git", "tag", "--points-at", OPENHANDS_COMMIT_SHA],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode == 0 and result.stdout.strip():
            # This commit is exactly a tag, use that version
            tags = [t for t in result.stdout.strip().split("\n") if t.strip()]
            version_tags = [t for t in tags if t.startswith("0.")]
            if version_tags:
                return version_tags[0]  # Use the first version tag

        # Find the latest tag that's an ancestor of our commit and count commits after it
        result = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0", OPENHANDS_COMMIT_SHA],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode == 0 and result.stdout.strip():
            latest_tag = result.stdout.strip()

            # Count commits from that tag to our commit
            result = subprocess.run(
                ["git", "rev-list", f"{latest_tag}..{OPENHANDS_COMMIT_SHA}", "--count"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=False,
            )

            if result.returncode == 0:
                commits_after = int(result.stdout.strip())
                if commits_after > 0:
                    return f"{latest_tag}-post{commits_after}-{OPENHANDS_COMMIT_SHA}"
                else:
                    # We're exactly at the tag
                    return latest_tag

        # Final fallback
        repo_version = _get_repo_version_at_commit()
        return f"{repo_version}-{OPENHANDS_COMMIT_SHA}"

    except:
        # Ultimate fallback
        repo_version = _get_repo_version_at_commit()
        return f"{repo_version}-{OPENHANDS_COMMIT_SHA}"


def get_commit_sha() -> str:
    """Get the OpenHands commit SHA to build from."""
    return OPENHANDS_COMMIT_SHA


def get_full_sha() -> str:
    """Get the full OpenHands commit SHA."""
    return OPENHANDS_FULL_SHA


def get_version_tag() -> str:
    """Get a version tag combining version and commit SHA."""
    return f"{get_version()}-vendored"


def get_repo_version() -> str:
    """Get just the repo version without commit info."""
    return _get_repo_version_at_commit()


def get_version_info() -> dict[str, str | None]:
    """Get comprehensive version information."""
    return {
        "version": get_version(),
        "commit_sha": OPENHANDS_COMMIT_SHA,
        "full_sha": OPENHANDS_FULL_SHA,
        "repo_version": get_repo_version(),
    }
