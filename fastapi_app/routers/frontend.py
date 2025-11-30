from typing import Optional, List
from pathlib import Path
from urllib.parse import quote
from fastapi import APIRouter, Request, Depends, Form, status, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, Response, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select
from ..core.database import get_session
from ..core.security import settings, create_access_token, verify_password, get_password_hash
from ..core.logging import log_conversion_error, log_auth_event
from ..models.user import User
from ..models.conversion import Conversion
from ..schemas.conversion import ConversionRead
from ..services.converter import Convert2Pcap
from datetime import timedelta
from jose import jwt, JWTError
import os


# Windows reserved filenames
WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4",
                    "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2",
                    "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"}
MAX_FILENAME_LENGTH = 255


def sanitize_filename(filename: str) -> str:
    """Comprehensive filename sanitization."""
    if not filename:
        raise ValueError("Filename cannot be empty")
    filename = os.path.basename(filename)
    filename = filename.replace("\x00", "")
    sanitized = "".join(c for c in filename if c.isalnum() or c in "._-")
    if not sanitized or len(sanitized) > MAX_FILENAME_LENGTH:
        raise ValueError("Invalid filename length")
    name_without_ext = sanitized.rsplit(".", 1)[0].upper()
    if name_without_ext in WINDOWS_RESERVED:
        raise ValueError("Reserved filename not allowed")
    if sanitized.startswith(".") or sanitized in {".", ".."}:
        sanitized = "file_" + sanitized
    return sanitized


def get_safe_content_disposition(filename: str) -> str:
    """Generate RFC 5987 compliant Content-Disposition header value."""
    encoded_filename = quote(filename, safe="")
    return f"attachment; filename*=UTF-8''{encoded_filename}"

BASE_DIR = Path(__file__).resolve().parent.parent

router = APIRouter()  # Full router with template-based handlers
api_router = APIRouter()  # API-only router for React frontend
templates = Jinja2Templates(directory=BASE_DIR / "templates")

def get_current_user_from_cookie(request: Request, session: Session) -> Optional[User]:
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        scheme, _, param = token.partition(" ")
        payload = jwt.decode(param, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
    except JWTError:
        return None
    
    statement = select(User).where(User.email == email)
    user = session.exec(statement).first()
    return user

@router.get("/", response_class=HTMLResponse)
async def home(request: Request, session: Session = Depends(get_session)):
    user = get_current_user_from_cookie(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    
    statement = select(Conversion).where(Conversion.user_id == user.id)
    tasks = session.exec(statement).all()
    
    return templates.TemplateResponse("convert.html", {"request": request, "user": user, "tasks": tasks})

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "user": None})

@router.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, email: str = Form(...), password: str = Form(...), session: Session = Depends(get_session)):
    client_ip = request.client.host if request.client else "unknown"
    statement = select(User).where(User.email == email)
    user = session.exec(statement).first()
    if not user or not verify_password(password, user.hashed_password):
        log_auth_event("LOGIN", email, success=False, ip_address=client_ip, details="Invalid credentials")
        return templates.TemplateResponse("login.html", {"request": request, "user": None, "error": "Incorrect email or password"})

    log_auth_event("LOGIN", email, success=True, ip_address=client_ip)
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )

    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        secure=settings.ENVIRONMENT == "production",
        samesite="strict",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return response

@router.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("access_token")
    return response

@router.get("/sign-up", response_class=HTMLResponse)
async def signup_page(request: Request):
    return templates.TemplateResponse("sign_up.html", {"request": request, "user": None})

@router.post("/sign-up", response_class=HTMLResponse)
async def signup_submit(
    request: Request,
    email: str = Form(...),
    firstName: str = Form(...),
    password1: str = Form(...),
    password2: str = Form(...),
    session: Session = Depends(get_session)
):
    client_ip = request.client.host if request.client else "unknown"
    if password1 != password2:
        return templates.TemplateResponse("sign_up.html", {"request": request, "user": None, "error": "Passwords do not match"})

    # Password strength validation
    if len(password1) < 12:
        return templates.TemplateResponse("sign_up.html", {"request": request, "user": None, "error": "Password must be at least 12 characters"})
    if not any(c.isupper() for c in password1):
        return templates.TemplateResponse("sign_up.html", {"request": request, "user": None, "error": "Password must contain an uppercase letter"})
    if not any(c.islower() for c in password1):
        return templates.TemplateResponse("sign_up.html", {"request": request, "user": None, "error": "Password must contain a lowercase letter"})
    if not any(c.isdigit() for c in password1):
        return templates.TemplateResponse("sign_up.html", {"request": request, "user": None, "error": "Password must contain a number"})

    statement = select(User).where(User.email == email)
    existing_user = session.exec(statement).first()
    if existing_user:
        return templates.TemplateResponse("sign_up.html", {"request": request, "user": None, "error": "Email already registered"})

    hashed_password = get_password_hash(password1)
    new_user = User(email=email, hashed_password=hashed_password, first_name=firstName)
    session.add(new_user)
    session.commit()

    log_auth_event("SIGNUP", email, success=True, ip_address=client_ip)

    # Auto login
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": new_user.email}, expires_delta=access_token_expires
    )

    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        secure=settings.ENVIRONMENT == "production",
        samesite="strict",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return response

# File upload (cookie-based auth for web forms)
@router.post("/upload/")
async def upload_files(request: Request, session: Session = Depends(get_session)):
    user = get_current_user_from_cookie(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    # Get form data to handle various file input names
    form = await request.form()
    files = form.getlist("files")

    for file in files:
        content = await file.read()
        try:
            filename = sanitize_filename(file.filename)
        except ValueError:
            filename = "uploaded_file"
        conversion = Conversion(content=filename, data=content, user_id=user.id)
        session.add(conversion)
    session.commit()

    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

# Convert file (cookie-based auth)
@router.get("/convert/{id}")
async def convert_file(id: int, request: Request, session: Session = Depends(get_session)):
    user = get_current_user_from_cookie(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    conversion = session.get(Conversion, id)
    if not conversion or conversion.user_id != user.id:
        raise HTTPException(status_code=404, detail="Conversion task not found")

    try:
        pcap_path, packets = Convert2Pcap.run_conversion(
            tid=conversion.id,
            cid=user.id,
            tuid=conversion.user_id,
            fname=conversion.content,
            file_to_convert=conversion.data
        )

        with open(pcap_path, "rb") as f:
            conversion.data_converted = f.read()

        session.add(conversion)
        session.commit()
        os.remove(pcap_path)
    except Exception as e:
        log_conversion_error(id, user.id, e)
        raise HTTPException(
            status_code=500,
            detail="Conversion failed. Please check your file format and try again."
        )

    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

# Download original file
@router.get("/download/{id}")
async def download_original(id: int, request: Request, session: Session = Depends(get_session)):
    user = get_current_user_from_cookie(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    conversion = session.get(Conversion, id)
    if not conversion or conversion.user_id != user.id:
        raise HTTPException(status_code=404, detail="Conversion task not found")

    return Response(
        content=conversion.data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": get_safe_content_disposition(conversion.content)}
    )

# Download PCAP file
@router.get("/download-pcap/{id}")
async def download_pcap(id: int, request: Request, session: Session = Depends(get_session)):
    user = get_current_user_from_cookie(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    conversion = session.get(Conversion, id)
    if not conversion or conversion.user_id != user.id:
        raise HTTPException(status_code=404, detail="Conversion task not found")

    if not conversion.data_converted:
        raise HTTPException(status_code=400, detail="File not converted yet")

    return Response(
        content=conversion.data_converted,
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": get_safe_content_disposition(f"{conversion.content}.pcap")}
    )

# Delete conversion
@router.get("/delete/{id}")
async def delete_conversion(id: int, request: Request, session: Session = Depends(get_session)):
    user = get_current_user_from_cookie(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    conversion = session.get(Conversion, id)
    if not conversion or conversion.user_id != user.id:
        raise HTTPException(status_code=404, detail="Conversion task not found")

    session.delete(conversion)
    session.commit()

    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

# Rename conversion (cookie-based auth for JS fetch)
@router.post("/rename/{id}")
async def rename_conversion(id: int, request: Request, session: Session = Depends(get_session)):
    user = get_current_user_from_cookie(request, session)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    conversion = session.get(Conversion, id)
    if not conversion or conversion.user_id != user.id:
        raise HTTPException(status_code=404, detail="Conversion task not found")

    body = await request.json()
    new_name = body.get("new_name", "")

    # Sanitize filename with comprehensive validation
    try:
        new_name = sanitize_filename(new_name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    conversion.content = new_name
    session.add(conversion)
    session.commit()

    return {"message": "Renamed successfully"}

# API endpoints for React frontend
# These are registered on both routers for compatibility

async def _get_current_user_api(request: Request, session: Session = Depends(get_session)):
    user = get_current_user_from_cookie(request, session)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {
        "id": user.id,
        "email": user.email,
        "first_name": user.first_name,
    }

async def _get_conversions_api(request: Request, session: Session = Depends(get_session)):
    user = get_current_user_from_cookie(request, session)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    statement = select(Conversion).where(Conversion.user_id == user.id)
    conversions = session.exec(statement).all()
    return [
        ConversionRead(
            content=c.content,
            id=c.id,
            date_created=c.date_created,
            user_id=c.user_id,
            has_converted_data=c.data_converted is not None
        ) for c in conversions
    ]

# Register on main router (for template mode)
router.get("/api/me")(_get_current_user_api)
router.get("/api/conversions", response_model=List[ConversionRead])(_get_conversions_api)

# Register on api_router (for React mode)
api_router.get("/api/me")(_get_current_user_api)
api_router.get("/api/conversions", response_model=List[ConversionRead])(_get_conversions_api)

# API-compatible login/signup for React (returns JSON, not templates)
@api_router.post("/login")
async def api_login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session)
):
    client_ip = request.client.host if request.client else "unknown"
    statement = select(User).where(User.email == email)
    user = session.exec(statement).first()

    # Check account lockout
    if user and user.is_locked:
        log_auth_event("LOGIN", email, success=False, ip_address=client_ip, details="Account locked")
        raise HTTPException(status_code=429, detail="Account temporarily locked due to too many failed attempts")

    if not user or not verify_password(password, user.hashed_password):
        if user:
            user.record_failed_login()
            session.add(user)
            session.commit()
        log_auth_event("LOGIN", email, success=False, ip_address=client_ip, details="Invalid credentials")
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    # Reset failed attempts on success
    user.reset_failed_attempts()
    session.add(user)
    session.commit()

    log_auth_event("LOGIN", email, success=True, ip_address=client_ip)
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )

    response = JSONResponse(content={"success": True})
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        secure=settings.ENVIRONMENT == "production",
        samesite="strict",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return response

@api_router.post("/sign-up")
async def api_signup_submit(
    request: Request,
    email: str = Form(...),
    firstName: str = Form(...),
    password1: str = Form(...),
    password2: str = Form(...),
    session: Session = Depends(get_session)
):
    client_ip = request.client.host if request.client else "unknown"

    if password1 != password2:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    # Password strength validation
    if len(password1) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters")
    if not any(c.isupper() for c in password1):
        raise HTTPException(status_code=400, detail="Password must contain an uppercase letter")
    if not any(c.islower() for c in password1):
        raise HTTPException(status_code=400, detail="Password must contain a lowercase letter")
    if not any(c.isdigit() for c in password1):
        raise HTTPException(status_code=400, detail="Password must contain a number")

    statement = select(User).where(User.email == email)
    existing_user = session.exec(statement).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(password1)
    new_user = User(email=email, hashed_password=hashed_password, first_name=firstName)
    session.add(new_user)
    session.commit()

    log_auth_event("SIGNUP", email, success=True, ip_address=client_ip)

    # Auto login
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": new_user.email}, expires_delta=access_token_expires
    )

    response = JSONResponse(content={"success": True})
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        secure=settings.ENVIRONMENT == "production",
        samesite="strict",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return response

# Also register file operation routes on api_router for React mode
api_router.post("/upload/")(upload_files)
api_router.get("/convert/{id}")(convert_file)
api_router.get("/download/{id}")(download_original)
api_router.get("/download-pcap/{id}")(download_pcap)
api_router.get("/delete/{id}")(delete_conversion)
api_router.post("/rename/{id}")(rename_conversion)
api_router.get("/logout")(logout)
