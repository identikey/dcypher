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
import shutil

from main import (
    app,
)
from app_state import state
from config import BLOCK_STORE_ROOT, CHUNK_STORE_ROOT


@pytest.fixture(scope="function")
def free_port():
    """Finds and returns a free port on the host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="function")
def live_api_server(free_port, monkeypatch, tmp_path):
    """
    Starts the FastAPI app in a background thread for a test function.
    Uses a dynamically allocated port and the function-scoped temp path
    to ensure complete test isolation.
    """
    # Use the per-test tmp_path for storage
    block_store_path = tmp_path / "block_store"
    chunk_store_path = tmp_path / "chunk_store"
    block_store_path.mkdir()
    chunk_store_path.mkdir()

    # Monkeypatch the storage roots and clear in-memory stores for this test run
    monkeypatch.setattr("config.BLOCK_STORE_ROOT", str(block_store_path))
    monkeypatch.setattr("config.CHUNK_STORE_ROOT", str(chunk_store_path))
    state.accounts.clear()
    state.used_nonces.clear()
    state.graveyard.clear()
    state.block_store.clear()
    state.chunk_store.clear()

    api_base_url = f"http://127.0.0.1:{free_port}"
    os.environ["API_BASE_URL"] = api_base_url
    config = uvicorn.Config(app, host="127.0.0.1", port=free_port, log_level="warning")
    server = uvicorn.Server(config)
    ready_event = threading.Event()

    def run_server():
        server.run()

    thread = threading.Thread(target=run_server, daemon=True)

    # Patch server startup to set the ready event, so we know when it's up.
    original_startup = server.startup

    async def new_startup(sockets=None):
        await original_startup(sockets=sockets)
        ready_event.set()

    server.startup = new_startup
    thread.start()

    if not ready_event.wait(timeout=10):
        raise RuntimeError("Uvicorn server failed to start in time.")

    yield api_base_url

    # Teardown: stop the server thread
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture(scope="function")
def api_base_url(live_api_server):
    """Provides the base URL of the live test server for a given test."""
    return live_api_server


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
