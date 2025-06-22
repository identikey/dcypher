from fastapi import FastAPI

# To run this with uvicorn:
# uvicorn src.main:app --reload
# Ensure your PYTHONPATH is set up correctly if you have issues with the import.
# For example: export PYTHONPATH=.
from src.routers import accounts as accounts_router
from src.routers import storage as storage_router
from src.routers import system as system_router


def create_app() -> FastAPI:
    app = FastAPI()

    app.include_router(accounts_router.router, tags=["accounts"])
    app.include_router(storage_router.router, tags=["storage"])
    app.include_router(system_router.router, tags=["system"])

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)
