
import os
import random
from string import Template
from threading import Thread


class OTPManager:
    def __init__(self, email_manager) -> None:
        self.email_manager = email_manager
        self.OTP = None
        self.otp_template = None

    def generate_otp(self) -> int:
        """
        Generates random 6-digit number as OTP.
        """
        self.OTP = random.sample(range(10**6), 1)[0]
        return self.OTP

    def load_template(self, path="./html/template.html") -> Template:
        """
        Loads the HTML template from path and assigns it to otp_template
        """
        if not self.otp_template:
            with open(path, "r") as f:
                self.otp_template = Template(f.read())
        return self.otp_template

    def create_temp_html(self, path="./html/temp_password.html") -> None:
        template = self.load_template()
        edited_template = template.safe_substitute(code=self.OTP)
        with open(path, "w") as f:
            f.write(edited_template)

    def send_email(self, email: str, otp: int) -> None:
        """
        Creates Updated HTML & Calls send_email Thread
        """
        path = self.create_temp_html(otp)
        Thread(target=self.send_email_thread, args=(email, path)).start()

    def send_email_thread(self, email: str, file: str) -> None:
        """
        Sends email using threading.
        """
        self.email_manager.send_email(email, file)
        os.remove(file)

    def verify_OTP(self, OTP: int) -> bool:
        if self.OTP == OTP:
            return True
        return False
