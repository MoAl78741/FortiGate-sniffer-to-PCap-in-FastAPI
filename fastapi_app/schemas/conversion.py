from datetime import datetime
from pydantic import BaseModel, Field


class ConversionBase(BaseModel):
    """Base conversion schema with common fields."""

    content: str = Field(..., description="Filename of the sniffer file", examples=["capture.txt"])


class ConversionCreate(ConversionBase):
    """Schema for creating a new conversion task."""

    pass


class ConversionRead(ConversionBase):
    """Schema for reading conversion task data."""

    id: int = Field(..., description="Unique conversion task identifier", examples=[1])
    date_created: datetime = Field(..., description="When the file was uploaded")
    user_id: int = Field(..., description="ID of the user who owns this conversion")
    has_converted_data: bool = Field(
        ...,
        description="Whether the file has been converted to PCAP format",
        examples=[True],
    )

    class Config:
        from_attributes = True


class ConversionRename(BaseModel):
    """Schema for renaming a conversion task."""

    new_name: str = Field(
        ...,
        min_length=1,
        description="New filename for the conversion task",
        examples=["renamed_capture.txt"],
    )
