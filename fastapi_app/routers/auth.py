from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select
from slowapi import Limiter
from slowapi.util import get_remote_address
from ..core.database import get_session
from ..core.security import create_access_token, get_password_hash, verify_password
from ..core.config import settings
from ..core.logging import log_auth_event
from ..models.user import User
from ..schemas.token import Token
from ..schemas.user import UserCreate, UserRead

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

router = APIRouter()

@router.post(
    "/token",
    response_model=Token,
    summary="Login for access token",
    description="Authenticate with email and password to receive a JWT access token. Use this token in the Authorization header for protected endpoints.",
    responses={
        200: {"description": "Successfully authenticated, returns JWT token"},
        401: {"description": "Invalid email or password"},
        429: {"description": "Too many login attempts"},
    },
)
@limiter.limit("5/minute")
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
):
    """
    Authenticate user and return JWT token.

    - **username**: User's email address
    - **password**: User's password

    Rate limited to 5 attempts per minute.
    """
    client_ip = request.client.host if request.client else "unknown"
    statement = select(User).where(User.email == form_data.username)
    user = session.exec(statement).first()

    # Check if account is locked
    if user and user.is_locked:
        log_auth_event("LOGIN", form_data.username, success=False, ip_address=client_ip, details="Account locked")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked due to too many failed attempts. Try again later.",
        )

    if not user or not verify_password(form_data.password, user.hashed_password):
        # Record failed attempt if user exists
        if user:
            user.record_failed_login()
            session.add(user)
            session.commit()
        log_auth_event("LOGIN", form_data.username, success=False, ip_address=client_ip, details="Invalid credentials")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Successful login - reset failed attempts
    user.reset_failed_attempts()
    session.add(user)
    session.commit()

    log_auth_event("LOGIN", user.email, success=True, ip_address=client_ip)
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post(
    "/signup",
    response_model=UserRead,
    summary="Create new user account",
    description="Register a new user with email, password, and optional first name.",
    responses={
        200: {"description": "User created successfully"},
        400: {"description": "Email already registered or invalid password"},
        429: {"description": "Too many signup attempts"},
    },
)
@limiter.limit("3/hour")
async def create_user(
    request: Request,
    user: UserCreate,
    session: Session = Depends(get_session),
):
    """
    Create a new user account.

    - **email**: Valid email address (must be unique)
    - **password**: User's password (min 12 chars with uppercase, lowercase, and number)
    - **first_name**: Optional first name

    Rate limited to 3 signups per hour per IP.
    """
    client_ip = request.client.host if request.client else "unknown"
    statement = select(User).where(User.email == user.email)
    existing_user = session.exec(statement).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password, first_name=user.first_name)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    log_auth_event("SIGNUP", user.email, success=True, ip_address=client_ip)
    return db_user
