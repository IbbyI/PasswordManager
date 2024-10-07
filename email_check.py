import re
from tkinter import messagebox 

def email_check(email):
    regex = re.compile(r'^[a-zA-Z0-9.!#$%&` *+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$')
    if regex.match(email):
        print(f"{email} is a valid email.")
        return True
    else:
        messagebox.showerror("Error", "Error: 004 Please Enter a Valid Email Address.")
        return False