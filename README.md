# dCypher Recryption

dCypher is a project demonstrating proxy re-encryption (PRE).

## Development

This project uses [Just](https://github.com/casey/just) for task automation. Install it with:

```bash
brew install just
```

### Available Tasks

Run `just` to see all available tasks, or use these common commands:

- **`just dev`** - Run the CLI locally with uv
- **`just docker-build`** - Build the Docker image
- **`just docker-run`** - Run the Docker container
- **`just docker-bash`** - Open interactive bash shell in container
- **`just docker-exec <command>`** - Run a custom command in the container

### Examples

```bash
# Quick local development
just dev

# Build and test with Docker
just docker-build
just docker-run

# Debug in container
just docker-bash

# Run tests in container
just docker-exec "python -m pytest"
## Documentation

The detailed message specification can be found in [docs/spec.md](docs/spec.md).

## Library

The core PRE logic is implemented in `src/lib/pre.py`.

## Tests

To run the tests, execute the following command:

```bash
pytest
```
