
import os
import random
from string import Template
from threading import Thread


class OTPManager:
    def __init__(self, email_manager):
        self.email_manager = email_manager
        self.OTP = None
        self.otp_template = None


    # Generates OTP
    def generate_otp(self):
        self.OTP = random.sample(range(10**6), 1)[0]
        return self.OTP

    
    # Generate OTP HTML Template
    def load_template(self, path="./html/template.html"):
        if not self.otp_template:
            with open(path, "r") as f:
                self.otp_template = Template(f.read())
        return self.otp_template


    # Create Temporary OTP Email
    def create_temp_html(self, otp, path="./html/temp_password.html"):
        template = self.load_template()
        edited_template = template.safe_substitute(code=self.OTP) 
        with open(path, "w") as f:
            f.write(edited_template)
        return path
    

    # Creates Updated HTML & Calls send_email Thread
    def send_email(self, email, otp):
        path = self.create_temp_html(otp)
        Thread(target=self.send_email_thread, args=(email, path)).start()


    # Send Email Thread
    def send_email_thread(self, email, file):
        self.email_manager.send_email(email, file)
        os.remove(file)


    # Check OTP
    def verify_OTP(self, OTP):
        if self.OTP == OTP:
            return True
        return False
        
