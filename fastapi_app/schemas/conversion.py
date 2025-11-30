from typing import Optional
from datetime import datetime
from pydantic import BaseModel

class ConversionBase(BaseModel):
    content: str

class ConversionCreate(ConversionBase):
    pass

class ConversionRead(ConversionBase):
    id: int
    date_created: datetime
    user_id: int
    has_converted_data: bool

    class Config:
        from_attributes = True

class ConversionRename(BaseModel):
    new_name: str
