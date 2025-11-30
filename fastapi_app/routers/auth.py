from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select
from ..core.database import get_session
from ..core.security import create_access_token, get_password_hash, verify_password
from ..core.config import settings
from ..models.user import User
from ..schemas.token import Token
from ..schemas.user import UserCreate, UserRead

router = APIRouter()

@router.post(
    "/token",
    response_model=Token,
    summary="Login for access token",
    description="Authenticate with email and password to receive a JWT access token. Use this token in the Authorization header for protected endpoints.",
    responses={
        200: {"description": "Successfully authenticated, returns JWT token"},
        401: {"description": "Invalid email or password"},
    },
)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    """
    Authenticate user and return JWT token.

    - **username**: User's email address
    - **password**: User's password
    """
    statement = select(User).where(User.email == form_data.username)
    user = session.exec(statement).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
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
        400: {"description": "Email already registered"},
    },
)
async def create_user(user: UserCreate, session: Session = Depends(get_session)):
    """
    Create a new user account.

    - **email**: Valid email address (must be unique)
    - **password**: User's password
    - **first_name**: Optional first name
    """
    statement = select(User).where(User.email == user.email)
    existing_user = session.exec(statement).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password, first_name=user.first_name)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user
