import os, smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def send_email(email, file):
    # Sender's Email & Apps Password Hidden in Environment Variable
    my_email = os.environ.get("email")
    my_password = os.environ.get("appsPassword")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Password Manager"
    msg["From"] = my_email
    msg["To"] = email

    message = MIMEText(file, "html")
    msg.attach(message)
    context = ssl.create_default_context()

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(my_email, my_password)
        server.sendmail(my_email, email, message.as_string())
        print("Email Sent.")
