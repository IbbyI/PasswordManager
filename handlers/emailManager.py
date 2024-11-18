import os
import re
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


class EmailManager:
    def __init__(self, log_manager) -> None:
        """
        Manages password strength, email sending & validation.
        """
        self.log_manager = log_manager
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 465

    def send_email(self, recipient_email: str, file: str) -> None:
        """
        Sends email to recipient email using SMTP.
        """
        try:
            sender_email = os.environ.get("email")
            sender_password = os.environ.get("appsPassword")
            message = MIMEMultipart("alternative")
            message["Subject"] = "Password Manager"
            message["From"] = sender_email
            message["To"] = recipient_email

            with open(file, "r", encoding="utf-8") as f:
                html_content = f.read()

            html_text = MIMEText(html_content, "html")
            message.attach(html_text)

            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port) as server:
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, recipient_email,
                                message.as_string())
            print("Email sent successfully.")
        except smtplib.SMTPResponseException as e:
            self.log_manager.write_log(error_message=e)

    def is_valid_email(self, email: str) -> bool:
        """
        Checks if given email is valid using regex.
        """
        regex = re.compile(
            r'^[a-zA-Z0-9.!#$%&` *+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        )
        if regex.match(email):
            return True
        return False

    def strength(self, password: str) -> bool:
        """
        Compares given password to pwned password list.
        """
        url = "https://www.ncsc.gov.uk/static-assets/documents/PwnedPasswordsTop100k.json"
        response = requests.get(url)
        pass_list = set(response.json())

        if password in pass_list:
            return True
        return False
