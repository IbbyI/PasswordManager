import re
import smtplib
from string import Template
from typing import Optional
from threading import Thread
from getpass import getuser
from keyring import get_password

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from premailer import Premailer
from handlers.log_manager import LogManager


class EmailManager:
    """
    Manages SMTP settings as well as formatting, composing, and sending emails
    """

    def __init__(self, log_manager: LogManager) -> None:
        """
        Manages password strength, email sending & validation.
        Args:
            log_manager: The log manager object.
        """
        self.log_manager = log_manager
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 465
        self._cache_regex()

    def _cache_regex(self) -> None:
        """
        Caches the regex for email validation to improve performance.
        This method is called during initialization.
        """
        self.email_regex = re.compile(
            r"^[a-zA-Z0-9.!#$%&` *+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
        )

    def send_email(
        self,
        recipient_email: str,
        file_path: str,
        otp: Optional[int] = None,
        number_of_accounts: Optional[int] = None,
    ) -> None:
        """
        Sends an email to the recipient using SMTP with improved performance.
        Args:
            recipient_email (str): The recipient's email address.
            file_path (str): The path to the email template file.
            otp (int, optional): The OTP to be sent. Defaults to None.
            number_of_accounts (int, optional): The number of accounts to be sent. Defaults to None.
        """
        try:
            sender_email = get_password("sender_email", getuser())
            sender_password = get_password("app_password", getuser())

            if not sender_email or not sender_password:
                self.log_manager.log(
                    "Error", "Missing email credentials in environment variables"
                )
                return

            message = MIMEMultipart("alternative")
            message["Subject"] = "Password Manager"
            message["From"] = sender_email
            message["To"] = recipient_email

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    html_content = f.read()
            except FileNotFoundError:
                self.log_manager.log("Error", f"Email template not found: {file_path}")
                return

            try:
                username = recipient_email.split("@")[0]
                substitutions = {"user": username}

                if otp is not None:
                    substitutions["otp"] = str(otp)
                if number_of_accounts is not None:
                    substitutions["number_of_accounts"] = str(number_of_accounts)

                html_content_inlined = Premailer(
                    html_content, remove_classes=True
                ).transform()

                template = Template(html_content_inlined)
                formatted_html = template.safe_substitute(substitutions)

                html_part = MIMEText(formatted_html, "html")
                message.attach(html_part)
            except Exception as e:
                self.log_manager.log("Error", f"Template processing error: {e}")
                return

            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port) as server:
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, recipient_email, message.as_string())

            self.log_manager.log(
                "info", f"Email sent successfully to {recipient_email}"
            )
        except smtplib.SMTPResponseException as error:
            self.log_manager.log(
                "Error", f"SMTP error sending email to {recipient_email}: {error}"
            )
        except Exception as e:
            self.log_manager.log("Error", f"Unexpected error sending email: {e}")

    def send_email_async(
        self,
        recipient_email: str,
        file_path: str,
        otp: Optional[int] = None,
        number_of_accounts: Optional[int] = None,
    ) -> Thread:
        """
        Starts a thread to send an email asynchronously.
        Args:
            recipient_email (str): The recipient's email address.
            file_path (str): The path to the email template file.
            otp (Optional[int]): The OTP code if applicable.
            number_of_accounts (Optional[int]): The number of accounts if applicable.
        """
        email_thread = Thread(
            target=self.send_email,
            args=(recipient_email, file_path, otp, number_of_accounts),
            daemon=True,
        )
        email_thread.start()
        return email_thread

    def is_valid_email(self, email: str) -> bool:
        """
        Checks if given email is valid using regex.
        Args:
            email (str): The email to be validated.
        Returns:
            bool: True if email is valid, False otherwise.
        """
        if self.email_regex.match(email):
            return True
        return False
