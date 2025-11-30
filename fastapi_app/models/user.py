from typing import Optional, List, TYPE_CHECKING
from sqlmodel import SQLModel, Field, Relationship

if TYPE_CHECKING:
    from .conversion import Conversion

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str
    first_name: Optional[str] = None
    
    conversions: List["Conversion"] = Relationship(back_populates="user")
    
    @property
    def is_authenticated(self) -> bool:
        return True
