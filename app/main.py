from fastapi import FastAPI

from .routes.auth_test import router as auth_test_router
from .routes.health import router as health_router
from .settings import get_settings

settings = get_settings()

app = FastAPI(title="CloudArena API", version="0.1.0")
app.include_router(health_router)
app.include_router(auth_test_router)


@app.get("/")
async def root() -> dict[str, str]:
    return {"message": f"CloudArena API running in {settings.env} mode"}
