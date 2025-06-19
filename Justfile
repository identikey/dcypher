# DCypher Development Tasks

# Show available tasks
default:
    @just --list

# Build the Docker image
docker-build:
    docker buildx build --platform linux/amd64 -t dcypher --load .

# Run the Docker container
docker-run:
    docker run --rm dcypher

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
