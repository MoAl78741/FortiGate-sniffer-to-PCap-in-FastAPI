from typing import Optional
from datetime import datetime
from sqlmodel import SQLModel, Field, Relationship
from .user import User

class Conversion(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    content: str  # Filename
    data: bytes
    date_created: datetime = Field(default_factory=datetime.utcnow)
    data_converted: Optional[bytes] = None
    user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    
    user: Optional[User] = Relationship(back_populates="conversions")
