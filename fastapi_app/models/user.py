from typing import Optional, List, TYPE_CHECKING
from datetime import datetime, timedelta
from sqlmodel import SQLModel, Field, Relationship

if TYPE_CHECKING:
    from .conversion import Conversion

# Account lockout settings
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str
    first_name: Optional[str] = None

    # Account lockout fields
    failed_login_attempts: int = Field(default=0)
    locked_until: Optional[datetime] = Field(default=None)

    conversions: List["Conversion"] = Relationship(back_populates="user")

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_locked(self) -> bool:
        """Check if account is currently locked."""
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until

    def record_failed_login(self) -> None:
        """Record a failed login attempt and lock if threshold exceeded."""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            self.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)

    def reset_failed_attempts(self) -> None:
        """Reset failed login counter after successful login."""
        self.failed_login_attempts = 0
        self.locked_until = None
