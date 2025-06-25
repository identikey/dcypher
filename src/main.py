import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI

# To run this with uvicorn:
# uvicorn src.main:app --reload
# Ensure your PYTHONPATH is set up correctly if you have issues with the import.
# For example: export PYTHONPATH=.
from routers import accounts as accounts_router
from routers import storage as storage_router
from routers import system as system_router
from routers import reencryption as reencryption_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager. This is the recommended way to handle
    startup and shutdown events in modern FastAPI.
    """
    print("Starting background task for expired upload cleanup...")
    # Create a background task that runs for the entire application lifespan
    cleanup_task = asyncio.create_task(storage_router.cleanup_expired_pending_uploads())

    yield

    # On shutdown, cancel the background task
    print("Shutting down background task...")
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        print("Cleanup task successfully cancelled.")


def create_app() -> FastAPI:
    app = FastAPI(lifespan=lifespan)

    app.include_router(accounts_router.router, tags=["accounts"])
    app.include_router(storage_router.router, tags=["storage"])
    app.include_router(system_router.router, tags=["system"])
    app.include_router(reencryption_router.router, tags=["reencryption"])

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)
