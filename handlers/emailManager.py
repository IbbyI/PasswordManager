import os, re, requests, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class EmailManager:
    def __init__(self):
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 465
    

    # Sends Email Using SMTP
    def send_email(self, recipient_email, file):
        try:
            sender_email = os.environ.get("email")
            sender_password = os.environ.get("appsPassword")
            message = MIMEMultipart("alternative")
            message["Subject"] = "Account Information"
            message["From"] = sender_email
            message["To"] = recipient_email

            html_text = MIMEText(file, "html")
            message.attach(html_text)

            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port) as server:
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, recipient_email, message.as_string())
            print("Email sent successfully.")
        except smtplib.SMTPResponseException as e:
            print(f"Failed to send email: {e}")


    # Checks if Email is Valid
    def is_valid_email(self, email):
        regex = re.compile(r'^[a-zA-Z0-9.!#$%&` *+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$')
        if regex.match(email):
            return True
        return False

    # Checks Password Against Pwned Password List
    def strength(self, password):
        url = "https://www.ncsc.gov.uk/static-assets/documents/PwnedPasswordsTop100k.json"
        response = requests.get(url)
        pass_list = response.json()

        for i in pass_list:
            if i == password:
                return True