from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from cve_genie_web.database import initialize_database
from cve_genie_web.routes.jobs import router as jobs_router


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


app = FastAPI(
    title="CVE-Genie Web",
    version="0.1.0",
    description="Web API wrapper for CVE-Genie reproduction jobs",
)

app.include_router(jobs_router)

app.mount(
    "/static",
    StaticFiles(directory=str(STATIC_DIR)),
    name="static",
)


@app.on_event("startup")
def startup_event() -> None:
    initialize_database()


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}