import logging
import sys
from datetime import datetime
from .config import settings

# Configure logging format
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Set up root logger
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)

# Create loggers for different components
auth_logger = logging.getLogger("auth")
conversion_logger = logging.getLogger("conversion")
security_logger = logging.getLogger("security")


def log_auth_event(
    event_type: str,
    email: str,
    success: bool,
    ip_address: str = None,
    details: str = None,
):
    """Log authentication-related events for audit trail."""
    message = f"AUTH:{event_type} | email={email} | success={success}"
    if ip_address:
        message += f" | ip={ip_address}"
    if details:
        message += f" | details={details}"

    if success:
        auth_logger.info(message)
    else:
        auth_logger.warning(message)


def log_security_event(event_type: str, details: str, severity: str = "warning"):
    """Log security-related events."""
    message = f"SECURITY:{event_type} | {details}"
    if severity == "critical":
        security_logger.critical(message)
    elif severity == "error":
        security_logger.error(message)
    elif severity == "warning":
        security_logger.warning(message)
    else:
        security_logger.info(message)


def log_conversion_error(task_id: int, user_id: int, error: Exception):
    """Log conversion errors internally without exposing details to users."""
    conversion_logger.error(
        f"CONVERSION:FAILED | task_id={task_id} | user_id={user_id} | error={str(error)}",
        exc_info=True,
    )
