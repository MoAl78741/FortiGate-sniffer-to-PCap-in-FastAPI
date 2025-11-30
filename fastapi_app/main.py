from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from .core.config import settings
from .core.database import create_db_and_tables
from .routers import auth, conversion, frontend

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent / "frontend" / "dist"
USE_REACT = FRONTEND_DIR.exists() and (FRONTEND_DIR / "index.html").exists()


# Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        # XSS protection (legacy browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'"
        )
        # HSTS (only in production with HTTPS)
        if settings.ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


# Disable OpenAPI docs in production
docs_url = "/docs" if settings.DEBUG or settings.ENVIRONMENT != "production" else None
redoc_url = "/redoc" if settings.DEBUG or settings.ENVIRONMENT != "production" else None
openapi_url = "/openapi.json" if settings.DEBUG or settings.ENVIRONMENT != "production" else None

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="""
## FortiGate Sniffer to PCAP Converter API

Convert FortiGate network sniffer output files to Wireshark-compatible PCAP format.

### Features
- **User Authentication**: Secure JWT-based authentication with strong password requirements
- **File Upload**: Upload FortiGate sniffer text files (.txt, .log, .sniffer, .cap, .dump)
- **Conversion**: Convert sniffer output to PCAPNG format
- **Download**: Download original or converted files

### Security
- Rate limiting on authentication endpoints (5 login attempts/minute, 3 signups/hour)
- Account lockout after 5 failed login attempts (15 minute lockout)
- Strong password requirements (12+ chars, mixed case, numbers)
- Filename sanitization and validation
- Security headers (CSP, X-Frame-Options, HSTS in production)

### Authentication
Most endpoints require a valid JWT token. Obtain one via the `/token` endpoint using your email and password.

Include the token in the `Authorization` header: `Bearer <your-token>`
""",
    version="1.0.0",
    contact={
        "name": "API Support",
    },
    license_info={
        "name": "MIT",
    },
    docs_url=docs_url,
    redoc_url=redoc_url,
    openapi_url=openapi_url,
)

# Add security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:8000"] if settings.DEBUG else [],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

# Rate limiting setup
app.state.limiter = auth.limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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

    # Include only API endpoints from frontend router (not template-based handlers)
    app.include_router(frontend.api_router)
else:
    # Development with templates: include full frontend router
    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
    app.include_router(frontend.router)
