from typing import Optional
from pydantic import BaseModel, Field


class Token(BaseModel):
    """JWT token response schema."""

    access_token: str = Field(..., description="JWT access token for authentication")
    token_type: str = Field(..., description="Token type (always 'bearer')", examples=["bearer"])


class TokenData(BaseModel):
    """Token payload data schema."""

    email: Optional[str] = Field(None, description="User's email extracted from token")
