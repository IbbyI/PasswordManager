import os
import random
from string import Template
from threading import Thread
from typing import Optional


class OTPManager:
    def __init__(self, email_manager, log_manager) -> None:
        self.email_manager = email_manager
        self.log_manager = log_manager
        self.OTP: Optional[int] = None
        self.otp_template: Optional[Template] = None

    def generate_otp(self) -> int:
        """
        Generates a random 6-digit number as OTP.
        """
        self.OTP = random.sample(range(10**6), 1)[0]
        return self.OTP

    def load_template(self, path="./html/template.html") -> Template:
        """
        Loads the HTML template from the given path and assigns it to otp_template.
        Raises FileNotFoundError if the template file is missing.
        """
        if not self.otp_template:
            try:
                with open(path, "r") as f:
                    self.otp_template = Template(f.read())
            except FileNotFoundError:
                self.log_manager.write_log(
                    error_message=f"Template file not found at: {path}")
                raise FileNotFoundError(f"Template file not found at: {path}")
        return self.otp_template

    def create_temp_html(self) -> str:
        """
        Creates a temporary HTML file with the OTP substituted and returns its path.
        """
        if not self.OTP:
            self.log_manager.write_log(
                error_message="OTP has not been generated. Please call generate_otp first.")
            raise ValueError(
                "OTP has not been generated. Please call generate_otp first.")
        template = self.load_template()
        temp_path = "./html/temp_password.html"

        try:
            edited_template = template.safe_substitute(code=self.OTP)
            with open(temp_path, "w") as f:
                f.write(edited_template)
        except Exception as e:
            raise IOError(f"Failed to create temporary HTML file: {e}")

        return temp_path

    def send_email(self, email: str) -> None:
        """
        Creates the updated HTML file and starts a thread to send the email.
        """
        try:
            temp_file = self.create_temp_html()
            Thread(target=self.send_email_thread,
                   args=(email, temp_file)).start()
        except Exception as e:
            self.log_manager.write_log(
                error_message=f"Failed to send email: {e}")
            raise RuntimeError(f"Failed to send email: {e}")

    def send_email_thread(self, email: str, file: str) -> None:
        """
        Sends an email in a separate thread and safely deletes the temporary file.
        """
        try:
            self.email_manager.send_email(email, file)
        except Exception as e:
            self.log_manager.write_log(
                error_message=f"Failed to send email: {e}")
        finally:
            if os.path.exists(file):
                os.remove(file)

    def verify_otp(self, otp: int) -> bool:
        """
        Verifies if the provided OTP matches the generated OTP.
        """
        return self.OTP == otp
