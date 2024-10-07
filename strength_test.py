import requests
from tkinter import messagebox

def strength(password):
    url = "https://www.ncsc.gov.uk/static-assets/documents/PwnedPasswordsTop100k.json"
    try:
        response = requests.get(url)
        pass_list = response.json()
    except ValueError:
        messagebox.showerror("Error", "Error 006: Could not open JSON File.")

    for i in pass_list:
        if i == password:
            messagebox.showwarning("Leaked Password", "Your password has been leaked.\nConsider changing your password.")
