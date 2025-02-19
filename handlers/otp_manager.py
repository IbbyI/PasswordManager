import secrets
from typing import Optional


class OTPManager:
    def __init__(self, email_manager, log_manager) -> None:
        self.email_manager = email_manager
        self.log_manager = log_manager
        self.OTP: Optional[int] = None
        self.template: Optional[str] = None

    def generate_otp(self) -> int:
        """
        Generates a random 6-digit number as OTP.
        """
        self.OTP = secrets.randbelow(900000) + 100000
        return self.OTP

    def verify_otp(self, otp: int) -> bool:
        """
        Verifies if the provided OTP matches the generated OTP.
        """
        return self.OTP == otp
