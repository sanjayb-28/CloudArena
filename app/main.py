from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from .routes.auth_test import router as auth_test_router
from .routes.events import router as events_router
from .routes.facts import router as facts_router
from .routes.health import router as health_router
from .routes.reports import router as reports_router
from .routes.runs import router as runs_router
from .routes.ui import router as ui_router
from .settings import get_settings
from .store import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    init_db(settings.database_url)
    app.state.settings = settings
    yield


app = FastAPI(title="CloudArena API", version="0.1.0", lifespan=lifespan)
app.include_router(health_router)
app.include_router(auth_test_router)
app.include_router(facts_router)
app.include_router(events_router)
app.include_router(runs_router)
app.include_router(reports_router)
app.include_router(ui_router)


@app.get("/")
async def root(request: Request) -> dict[str, str]:
    settings = getattr(request.app.state, "settings", get_settings())
    return {"message": f"CloudArena API running in {settings.env} mode"}
