import pytest
import subprocess
import os
from pathlib import Path
import sys
import socket
import threading
import uvicorn
from fastapi.testclient import TestClient
import shutil
import pytest_asyncio
import uuid

# Add the project root to the Python path to allow imports from `src`
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dcypher.main import (
    app,
)
from dcypher.app_state import state
from dcypher.config import BLOCK_STORE_ROOT, CHUNK_STORE_ROOT

# Import TUI app after path is set up
try:
    from dcypher.tui.app import DCypherTUI
except ImportError:
    from dcypher.tui.app import DCypherTUI

# Global fixture for context manager test isolation
try:
    from dcypher.crypto.context_manager import CryptoContextManager
except ImportError:
    # Handle cases where src module isn't available
    try:
        from dcypher.crypto.context_manager import CryptoContextManager
    except ImportError:
        CryptoContextManager = None


def pytest_configure(config):
    """Configure pytest to handle crypto tests specially."""
    # Register the crypto marker if not already done
    config.addinivalue_line(
        "markers", "crypto: Crypto context tests that need sequential execution"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to handle crypto tests specially."""
    # Note: The original xdist_group approach didn't work as expected for forcing
    # sequential execution. However, the crypto tests now pass in parallel due to
    # other fixes (process-safe deserialization and proper context management).
    #
    # The tests marked with @pytest.mark.crypto are protected from context resets
    # by the reset_context_singleton fixture, which is sufficient for stability.
    pass


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
    monkeypatch.setattr("dcypher.config.BLOCK_STORE_ROOT", str(block_store_path))
    monkeypatch.setattr("dcypher.config.CHUNK_STORE_ROOT", str(chunk_store_path))
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

    # Use the installed dcypher command instead of the old cli.py file
    def run_command(cmd):
        full_cmd = ["uv", "run", "dcypher"] + cmd
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


@pytest.fixture
def api_client_factory(api_base_url, tmp_path):
    """
    Factory fixture that creates test API clients with identities.
    Returns a function that when called creates a new client/identity pair.
    """
    from dcypher.lib.api_client import DCypherClient
    from pathlib import Path
    import uuid

    # Counter to ensure unique names even if UUID somehow collides
    counter = 0

    def _create_client(additional_pq_algs=None):
        """
        Create a test client with identity and optionally create an account.

        Args:
            additional_pq_algs: List of additional PQ algorithms beyond ML-DSA

        Returns:
            tuple: (client, public_key_hex)
        """
        nonlocal counter
        counter += 1

        # Create a unique identity for this client using UUID and counter
        unique_suffix = f"{uuid.uuid4().hex[:8]}_{counter}"

        # Create unique subdirectory for this client's identity
        client_dir = tmp_path / f"client_{unique_suffix}"
        client_dir.mkdir()

        # Since create_test_account uses hardcoded "test_account" name,
        # we need to ensure each client gets its own directory
        client, public_key = DCypherClient.create_test_account(
            api_base_url, client_dir, additional_pq_algs=additional_pq_algs
        )

        return client, public_key

    return _create_client


@pytest.fixture
def temp_identity_dir(tmp_path):
    """
    Provides a temporary directory for storing identity files during tests.
    """
    identity_dir = tmp_path / "identities"
    identity_dir.mkdir(exist_ok=True)
    return identity_dir


@pytest_asyncio.fixture
async def tui_app():
    """Create a TUI app instance for testing."""
    app = DCypherTUI()

    # Use larger viewport to prevent OutOfBounds errors
    async with app.run_test(size=(160, 60)) as pilot:
        yield pilot
