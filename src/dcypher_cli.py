import sys
import os
from pathlib import Path

# Add the src directory to Python path
src_dir = Path(__file__).parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))


# Now import and run the CLI using dynamic import
def main():
    import importlib

    cli_module = importlib.import_module("cli.main")
    cli_module.cli()


if __name__ == "__main__":
    main()
