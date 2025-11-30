from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from .core.config import settings
from .core.database import create_db_and_tables
from .routers import auth, conversion, frontend

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent / "frontend" / "dist"
USE_REACT = FRONTEND_DIR.exists() and (FRONTEND_DIR / "index.html").exists()

app = FastAPI(title=settings.PROJECT_NAME)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# Always include API routes
app.include_router(auth.router, tags=["auth"])
app.include_router(conversion.router, tags=["conversion"])

if USE_REACT:
    # Production: Serve React frontend
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="react-assets")

    # Serve React app for frontend routes
    @app.get("/")
    async def serve_react_index():
        return FileResponse(FRONTEND_DIR / "index.html")

    @app.get("/login")
    async def serve_react_login():
        return FileResponse(FRONTEND_DIR / "index.html")

    @app.get("/signup")
    async def serve_react_signup():
        return FileResponse(FRONTEND_DIR / "index.html")

    # Include frontend router for API endpoints only (POST handlers, /api/*, etc.)
    app.include_router(frontend.router)
else:
    # Development with templates: include full frontend router
    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
    app.include_router(frontend.router)
