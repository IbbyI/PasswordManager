import os
import re
import smtplib
from string import Template
from typing import Optional
from threading import Thread

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

    def send_email(
        self,
        recipient_email: str,
        file_path: str,
        otp: Optional[int] = None,
        number_of_accounts: Optional[int] = None,
    ) -> None:
        """
        Sends an email to the recipient using SMTP.
        Args:
            recipient_email (str): The recipient's email address.
            file_path (str): The path to the email template file.
            otp (int, optional): The OTP to be sent. Defaults to None.
            number_of_accounts (int, optional): The number of accounts to be sent. Defaults to None.
        """
        try:
            sender_email = os.environ.get("email", "")
            sender_password = os.environ.get("app_password", "")

            message = MIMEMultipart("alternative")
            message["Subject"] = "Password Manager"
            message["From"] = sender_email
            message["To"] = recipient_email

            with open(file_path, "r", encoding="utf-8") as f:
                html_content = f.read()

            html_content_inlined = Premailer(
                html_content, remove_classes=True
            ).transform()

            template = Template(html_content_inlined)
            substitutions = {"user": recipient_email.split("@")[0]}
            if otp:
                substitutions["otp"] = str(otp)
            if number_of_accounts:
                substitutions["number_of_accounts"] = str(number_of_accounts)

            formatted_html = template.safe_substitute(substitutions)
            html_text = MIMEText((formatted_html), "html")
            message.attach(html_text)

            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port) as server:
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, recipient_email, message.as_string())
            self.log_manager.log("Error", "email test for log")
            print("Email sent successfully.")
        except smtplib.SMTPResponseException as error:
            self.log_manager.log("Error", f"Could Not Send Email: {error}")

    def send_email_thread(self, email: str, formatted_html: str) -> None:
        """
        Starts a thread to send an email.
        Args:
            email (str): The recipient's email address.
            formatted_html (str): The formatted HTML content to be sent.
        """
        Thread(target=self.send_email, args=(email, formatted_html, False)).start()

    def is_valid_email(self, email: str) -> bool:
        """
        Checks if given email is valid using regex.
        Args:
            email (str): The email to be validated.
        Returns:
            bool: True if email is valid, False otherwise.
        """
        regex = re.compile(
            r"^[a-zA-Z0-9.!#$%&` *+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
        )
        if regex.match(email):
            return True
        return False
