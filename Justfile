# DCypher Development Tasks

# Show available tasks
default:
    @just --list

# Build the Docker image
docker-built:
    docker build build --platform linux/amd64 -t dcypher --load .

# Build the development Docker image
docker-build-dev:
    docker buildx build --platform linux/amd64 -f dockerfile.dev -t dcypher-dev --load .

# Run the Docker container
docker-run:
    docker run --rm dcypher

# Start development environment with volume mounting
dev-up:
    docker-compose -f docker-compose.dev.yml up -d

# Stop development environment
dev-down:
    docker-compose -f docker-compose.dev.yml down

# Open an interactive bash shell in the development container
dev-shell:
    docker-compose -f docker-compose.dev.yml exec dcypher-dev bash

# Run tests in development container
dev-test:
    docker-compose -f docker-compose.dev.yml exec dcypher-dev uv run pytest tests/ -v

# Run CLI in development container
dev-cli *args:
    docker-compose -f docker-compose.dev.yml exec dcypher-dev uv run python src/cli.py {{args}}

# Rebuild and restart development environment
dev-rebuild:
    docker-compose -f docker-compose.dev.yml down
    docker-compose -f docker-compose.dev.yml build --no-cache
    docker-compose -f docker-compose.dev.yml up -d

# Open an interactive bash shell in the Docker container
docker-bash:
    docker run --rm -it dcypher bash

# Run the CLI locally with uv
cli *args:
    uv run python src/cli.py {{args}}

# Run the CLI in Docker container
docker-cli *args:
    docker run --rm -it dcypher uv run python src/cli.py {{args}}

# Run a custom command in the Docker container
docker-exec command:
    docker run --rm -it dcypher {{command}}

test:
    uv run pytest -n auto --dist worksteal tests/