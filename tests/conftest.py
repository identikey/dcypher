import pytest
import subprocess
import os
from pathlib import Path
import sys
import socket
import threading
import uvicorn
from fastapi.testclient import TestClient
import requests

from src.main import (
    app,
    accounts,
    used_nonces,
    graveyard,
    block_store,
    chunk_store,
)


@pytest.fixture(scope="session")
def free_port():
    """Finds and returns a free port on the host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def api_base_url(free_port):
    """Constructs the base URL for the API using the free port."""
    return f"http://127.0.0.1:{free_port}"


@pytest.fixture(scope="session", autouse=True)
def live_api_server(free_port, api_base_url):
    """
    Starts the FastAPI app in a background thread for the test session.
    Uses a dynamically allocated port to avoid conflicts, especially with pytest-xdist.
    """
    os.environ["API_BASE_URL"] = api_base_url
    config = uvicorn.Config(app, host="127.0.0.1", port=free_port, log_level="debug")
    server = uvicorn.Server(config)
    ready_event = threading.Event()

    def run_server():
        original_startup = server.startup

        async def new_startup(sockets=None):
            await original_startup(sockets=sockets)
            ready_event.set()

        server.startup = new_startup
        server.run()

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()

    if not ready_event.wait(timeout=10):
        raise RuntimeError("Uvicorn server failed to start in time.")

    yield


@pytest.fixture(autouse=True)
def cleanup_stores(request):
    """
    Cleans up the in-memory stores and on-disk storage on the live server
    before each test that uses the live server. It does this by making a
    request to a special test-only cleanup endpoint.
    """
    # Only run this for tests that use the live server.
    if "live_api_server" in request.fixturenames:
        api_base_url = request.getfixturevalue("api_base_url")
        try:
            # The actual cleanup happens on the server via this endpoint
            response = requests.post(f"{api_base_url}/test/cleanup")
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Failed to call the cleanup endpoint on the server: {e}")


@pytest.fixture(scope="module")
def api_client():
    """Provides a client for the FastAPI application."""
    with TestClient(app) as c:
        yield c


@pytest.fixture
def cli_test_env(tmp_path, request):
    """
    Sets up a test environment with a temporary directory and a helper for running CLI commands.
    """
    cli_path = Path(os.getcwd()) / "src" / "cli.py"

    def run_command(cmd):
        full_cmd = ["python3", str(cli_path)] + cmd
        result = subprocess.run(
            full_cmd, cwd=tmp_path, capture_output=True, text=True, check=False
        )

        if request.config.getoption("capture") == "no":
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr, file=sys.stderr)

        if result.returncode != 0:
            print("Error running command:", " ".join(full_cmd))
            print("Stdout:", result.stdout)
            print("Stderr:", result.stderr)
        return result

    return run_command, tmp_path
