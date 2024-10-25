import os
import tkinter as tk
import ttkbootstrap as tb
from tkinter import messagebox
from handlers.encryptionManager import EncryptionManager
from handlers.databaseManager import DatabaseManager
from handlers.emailManager import EmailManager


class MasterLogin:
    def __init__(self, login_success):
        self.encryption_manager = EncryptionManager()
        self.db_manager = DatabaseManager()
        self.email_manager= EmailManager()

        self.login_window = tk.Tk()
        self.login_window.title("Password Manager Login")
        self.login_window.resizable(False, False)
        self.login_window.geometry("300x200+550+150")

        self.style = tb.Style()
        self.style.theme_use("cyborg")

        self.mode(action="login")
        self.login_success = login_success
        self.login_window.mainloop()


    # Creates UI for Sign Up Window
    def signup_ui(self):
        for i in self.login_window.winfo_children():
            i.destroy()

        self.login_window.title("Password Manager Signup")

        tk.Label(self.login_window, text=" Enter your Email").pack()
        email_entry = tk.Entry(self.login_window)
        email_entry.pack(pady=3)

        tk.Label(self.login_window, text="Enter your Password").pack()
        password_entry = tk.Entry(self.login_window, show="*")
        password_entry.pack(pady=3)

        tk.Label(self.login_window, text="Confirm your Password").pack()
        confirm_password_entry = tk.Entry(self.login_window, show="*")
        confirm_password_entry.pack(pady=3)

        def validate_user():
            if password_entry.get() == confirm_password_entry.get():
                self.new_user_handler(email_entry.get(), password_entry.get())
            else:
                messagebox.showerror("Error", "Passwords do not match.")

            if not self.email_manager.is_valid_email(email_entry.get()):
                messagebox.showwarning("Invalid Email", "Please enter a valid email address.")
                return
        
        self.login_button = tk.Button(text="Register", command=validate_user())
        self.login_button.pack(pady=5)

        self.login_window.bind("<Return>", validate_user())

        login = tk.Button(self.login_window, text="Login", command=self.login_ui)
        login.pack(side="bottom", anchor="center")
        

    # Creates UI For Login Window
    def login_ui(self):
        for i in self.login_window.winfo_children():
            i.destroy()
        
        self.login_window.title("Password Manager Login")

        tk.Label(self.login_window, text="Email").pack()
        email_entry = tk.Entry(self.login_window)
        email_entry.pack(pady=3)

        tk.Label(self.login_window, text="Password").pack()
        password_entry = tk.Entry(self.login_window, show="*")
        password_entry.pack(pady=3)

        self.login_button = tk.Button(text="Log In", command= lambda: self.credentials_check(email_entry.get(), password_entry.get()))
        self.login_button.pack(pady=5)

        signup = tk.Button(self.login_window, text="Sign Up", command=self.signup_ui)
        signup.pack(side="bottom", anchor="center")

        self.login_window.bind("<Return>", self.credentials_check)


    # Changes the Window Mode Between Login/Signup
    def mode(self, action="signup"):
        if action == "signup":
            self.signup_ui()
        if action == "login":
            self.login_ui()

    
    # Checks If Given Login Details Are Valid
    def credentials_check(self, email, password):
        if not self.email_manager.is_valid_email(email):
            messagebox.showwarning("Invalid Email", "Please enter a valid email address.")
            return
        results = self.db_manager.search_user(email)
        salt = self.encryption_manager.generate_salt()

        if not results:
            messagebox.showerror("Invalid Credentials", "The username and password you entered do not match our records.")
            return
        
        hash = self.encryption_manager.hash_password(password, salt, iterations=10000)
        if hash == results[1]:
            print("logged in")
            self.login_success()


    # Handles New User Data
    def new_user_handler(self, email, password):
        salt = self.encryption_manager.generate_salt()
        hash = self.encryption_manager.hash_password(password, salt)
        self.db_manager.create_new_user(email, hash, salt)
        self.login_ui()
