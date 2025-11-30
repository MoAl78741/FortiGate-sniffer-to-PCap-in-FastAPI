from typing import Optional, List
from pathlib import Path
from fastapi import APIRouter, Request, Depends, Form, status, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, Response, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select
from ..core.database import get_session
from ..core.security import settings, create_access_token, verify_password, get_password_hash
from ..models.user import User
from ..models.conversion import Conversion
from ..schemas.conversion import ConversionRead
from ..services.converter import Convert2Pcap
from datetime import timedelta
from jose import jwt, JWTError
import os

BASE_DIR = Path(__file__).resolve().parent.parent

router = APIRouter()
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
    statement = select(User).where(User.email == email)
    user = session.exec(statement).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {"request": request, "user": None, "error": "Incorrect email or password"})
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
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
    if password1 != password2:
        return templates.TemplateResponse("sign_up.html", {"request": request, "user": None, "error": "Passwords do not match"})
    
    statement = select(User).where(User.email == email)
    existing_user = session.exec(statement).first()
    if existing_user:
        return templates.TemplateResponse("sign_up.html", {"request": request, "user": None, "error": "Email already registered"})
    
    hashed_password = get_password_hash(password1)
    new_user = User(email=email, hashed_password=hashed_password, first_name=firstName)
    session.add(new_user)
    session.commit()
    
    # Auto login
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": new_user.email}, expires_delta=access_token_expires
    )

    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
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
        filename = "".join(x for x in file.filename if x.isalnum() or x in "._-")
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
        raise HTTPException(status_code=500, detail=str(e))

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
        headers={"Content-Disposition": f"attachment; filename={conversion.content}"}
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
        headers={"Content-Disposition": f"attachment; filename={conversion.content}.pcap"}
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

    # Sanitize filename
    new_name = "".join(x for x in new_name if x.isalnum() or x in "._-")
    if not new_name:
        raise HTTPException(status_code=400, detail="Invalid filename")

    conversion.content = new_name
    session.add(conversion)
    session.commit()

    return {"message": "Renamed successfully"}

# API endpoints for React frontend
@router.get("/api/me")
async def get_current_user_api(request: Request, session: Session = Depends(get_session)):
    user = get_current_user_from_cookie(request, session)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {
        "id": user.id,
        "email": user.email,
        "first_name": user.first_name,
    }

@router.get("/api/conversions", response_model=List[ConversionRead])
async def get_conversions_api(request: Request, session: Session = Depends(get_session)):
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
