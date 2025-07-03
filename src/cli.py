# This file imports from the modular CLI structure
#
# Usage:
#   Module approach (recommended): uv run python -m src.cli
#   Direct approach: uv run python src/cli.py (may have import issues)
#
from cli.main import cli

if __name__ == "__main__":
    cli()
