from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class UserBase(BaseModel):
    """Base user schema with common fields."""

    email: EmailStr = Field(..., description="User's email address", examples=["user@example.com"])
    first_name: Optional[str] = Field(None, description="User's first name", examples=["John"])


class UserCreate(UserBase):
    """Schema for creating a new user account."""

    password: str = Field(
        ...,
        min_length=1,
        description="User's password",
        examples=["securepassword123"],
    )


class UserRead(UserBase):
    """Schema for reading user data (excludes password)."""

    id: int = Field(..., description="Unique user identifier", examples=[1])

    class Config:
        from_attributes = True
