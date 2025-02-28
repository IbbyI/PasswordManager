import secrets
from typing import Optional

from handlers.email_manager import EmailManager
from handlers.log_manager import LogManager


class OTPManager:
    """
    Manages OTP generation and verification.
    """

    def __init__(self, email_manager: EmailManager, log_manager: LogManager) -> None:
        """
        Initialize the OTPManager with dependencies.
        Args:
            email_manager: The email manager object.
            log_manager: The log manager object.
        """
        self.email_manager = email_manager
        self.log_manager = log_manager
        self.OTP: Optional[int] = None
        self.template: Optional[str] = None

    def generate_otp(self) -> int:
        """
        Generates a random 6-digit number as OTP.
        Returns:
            int: The generated OTP.
        """
        self.OTP = secrets.randbelow(900000) + 100000
        return self.OTP

    def verify_otp(self, otp: int) -> bool:
        """
        Verifies if the provided OTP matches the generated OTP.
        Args:
            otp (int): The OTP to be verified.
        Returns:
            bool: True if the OTP matches, False otherwise.
        """
        return self.OTP == otp
