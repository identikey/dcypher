import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI

# To run this with uvicorn:
# uvicorn src.main:app --reload
# Ensure your PYTHONPATH is set up correctly if you have issues with the import.
# For example: export PYTHONPATH=.
from dcypher.routers import accounts as accounts_router
from dcypher.routers import storage as storage_router
from dcypher.routers import system as system_router
from dcypher.routers import reencryption as reencryption_router
from dcypher.routers import crypto as crypto_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager. This is the recommended way to handle
    startup and shutdown events in modern FastAPI.
    """
    print("Starting up IDK server...")
    # Create a background task that runs for the entire application lifespan
    cleanup_task = asyncio.create_task(storage_router.cleanup_expired_pending_uploads())

    yield

    # On shutdown, cancel the background task
    print("Shutting down IDK server...")
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        print("Cleanup task successfully cancelled.")


def create_app() -> FastAPI:
    app = FastAPI(
        title="IDK Server",
        description="Identity Key Distribution server with proxy re-encryption",
        version="1.0.0",
        lifespan=lifespan,
    )

    app.include_router(accounts_router.router, tags=["accounts"])
    app.include_router(storage_router.router, tags=["storage"])
    app.include_router(system_router.router, tags=["system"])
    app.include_router(reencryption_router.router, tags=["reencryption"])
    app.include_router(crypto_router.router, tags=["crypto"])

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)
