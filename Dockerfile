# Use Ubuntu 24.04 for newer glibc (2.38+) required by OpenFHE
FROM ubuntu:24.04

# Install system dependencies required for OpenFHE
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install uv - the fast Python package manager
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Set working directory
WORKDIR /app

# Copy uv configuration files first for better Docker caching
COPY pyproject.toml uv.lock ./

# Install dependencies in production mode
# --no-dev excludes development dependencies
# --locked ensures we use the exact versions from uv.lock
RUN uv sync --locked --no-dev --no-install-project

# Copy the rest of the application code
COPY . .

# Install the project itself
RUN uv sync --locked --no-dev

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app"

# Run pytest on the tests directory
CMD ["uv", "run", "-m", "pytest", "tests/", "-v"]