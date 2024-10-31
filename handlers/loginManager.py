import os
import random
import tkinter as tk
import ttkbootstrap as tb
from string import Template
from threading import Thread
from tkinter import messagebox
from handlers.encryptionManager import EncryptionManager
from handlers.emailManager import EmailManager
from handlers.otpManager import OTPManager


class MasterLogin:
    def __init__(self, db_manager, login_success):
        self.db_manager = db_manager
        self.encryption_manager = EncryptionManager()        
        self.email_manager= EmailManager()
        self.otp_manager = OTPManager(self.email_manager)

        self.login_window = tk.Tk()
        self.login_window.title("Password Manager Login")
        self.login_window.resizable(False, False)
        self.login_window.geometry("320x220+550+150")

        self.style = tb.Style()
        self.style.theme_use("cyborg")

        self.OTP = None
        self.mode(action="login")
        self.login_success = login_success
        self.login_window.mainloop()


    # Changes the Window Mode Between Login/Signup
    def mode(self, action="signup"):
        if action == "signup":
            self.signup_ui()
        if action == "login":
            self.login_ui()
        if action == "forgot_password":
            self.forgot_password()


    # Creates UI for Sign Up Window
    def signup_ui(self):
        for i in self.login_window.winfo_children():
            i.destroy()

        self.login_window.title("Password Manager Signup")

        tk.Label(self.login_window, text=" Enter your Email:").pack()
        email_entry = tk.Entry(self.login_window, width=22)
        email_entry.pack(pady=3)

        tk.Label(self.login_window, text="Enter your Password:").pack()
        password_entry = tk.Entry(self.login_window, show="*", width=22)
        password_entry.pack(pady=3)

        tk.Label(self.login_window, text="Confirm your Password:").pack()
        confirm_password_entry = tk.Entry(self.login_window, show="*", width=22)
        confirm_password_entry.pack(pady=3)

        self.register_button = tk.Button(self.login_window, text="Register", command=lambda: self.validate_user(email_entry, password_entry, confirm_password_entry, action="new"))
        login = tk.Button(self.login_window, text="Login", command=self.login_ui)

        self.register_button.pack(pady=3)
        login.pack(anchor="center", side="bottom", pady=2)

        self.login_window.bind("<Return>", lambda event:self.validate_user(email_entry, password_entry, confirm_password_entry, action="new"))


    # Creates UI For Login Window
    def login_ui(self):
        for i in self.login_window.winfo_children():
            i.destroy()
        
        self.login_window.title("Password Manager Login")

        tk.Label(self.login_window, text="Email").pack()
        email_entry = tk.Entry(self.login_window, width=22)
        email_entry.pack(pady=3)

        tk.Label(self.login_window, text="Password").pack()
        password_entry = tk.Entry(self.login_window, show="*", width=22)
        password_entry.pack(pady=3)
    
        login_button = tk.Button(self.login_window, text="Log In", command= lambda: self.credentials_check(email_entry, password_entry))
        forgot_password = tk.Button(self.login_window, text="Forgot Password", command=lambda: self.forgot_password())
        signup = tk.Button(self.login_window, text="Sign Up", command=self.signup_ui)

        login_button.pack(pady=5)
        forgot_password.pack(side="bottom", anchor="center", pady=3)
        signup.pack(side="bottom", anchor="center")

        self.login_window.bind("<Return>", lambda event:self.credentials_check(email_entry, password_entry))


    # Checks if Email is Valid & Passwords Match
    def validate_user(self, email_entry, password_entry, confirm_entry, action="new"):
        if not self.email_manager.is_valid_email(email_entry.get()):
            messagebox.showwarning("Invalid Email", "Please enter a valid email address.")
            email_entry.config(highlightthickness=2, highlightbackground = "red", highlightcolor= "red")
            return

        if len(password_entry.get()) < 8 or self.email_manager.strength(password_entry.get()) is True:
            password_entry.config(highlightthickness=2, highlightbackground = "red", highlightcolor= "red")
            messagebox.showerror("Error", "Choose a Stronger Password")
            return

        if password_entry.get() == confirm_entry.get():
            if action == "new":
                self.new_user_handler(email_entry.get(), password_entry.get())
            if action == "reset":
                self.update_user_handler(email_entry.get(), password_entry.get())
        else:
            password_entry.config(highlightthickness=2, highlightbackground = "red", highlightcolor= "red")
            confirm_entry.config(highlightthickness=2, highlightbackground = "red", highlightcolor= "red")
            messagebox.showerror("Error", "Passwords do not match.")
    

    # Checks If Given Login Details Are Valid
    def credentials_check(self, email_entry, password_entry):
        email = email_entry.get()
        password = password_entry.get()
        if not self.email_manager.is_valid_email(email):
            email_entry.config(highlightthickness=2, highlightbackground = "red", highlightcolor= "red")            
            messagebox.showwarning("Invalid Email", "Please enter a valid email address.")
            return
        
        results = self.db_manager.search_user(email)
        if results:
             user_id = results[0]
        else:   
            email_entry.config(highlightthickness=2, highlightbackground = "red", highlightcolor= "red")
            password_entry.config(highlightthickness=2, highlightbackground = "red", highlightcolor= "red")
            messagebox.showerror("Invalid Credentials", "The username and password you entered do not match our records.")
            return
        
        hash = self.encryption_manager.hash_password(password, results[1], iterations=10000)
        if hash != results[2]:
            email_entry.config(highlightthickness=2, highlightbackground = "red", highlightcolor= "red")
            password_entry.config(highlightthickness=2, highlightbackground = "red", highlightcolor= "red")
            messagebox.showerror("Invalid Credentials", "The username and password you entered do not match our records.")
            return
        else:
            self.db_manager.set_user_id(user_id)
            self.login_window.withdraw()
            self.login_success()


    # Handles New User Data
    def new_user_handler(self, email, password):
        salt = self.encryption_manager.generate_salt()
        hash = self.encryption_manager.hash_password(password, salt)
        self.db_manager.create_new_user(email, hash, salt)
        self.login_ui()
        self.email_manager.send_email(email, file="./html/welcome.html")


    # Handles Updated User Data
    def update_user_handler(self, email, password):
        salt = self.encryption_manager.generate_salt()
        hash = self.encryption_manager.hash_password(password, salt)
        self.db_manager.update_user(email, hash, salt)
        self.login_ui()
        self.email_manager.send_email(email, file="./html/edit_data.html")
    

    # Forgot Password Feature
    def forgot_password(self):
        for i in self.login_window.winfo_children():
            i.destroy()

        self.login_window.title("Reset Password")

        tk.Label(self.login_window, text=" Enter your Email:").pack()
        self.forgot_email_entry = tk.Entry(self.login_window, width=22)
        self.forgot_email_entry.pack(pady=3)

        reset_password_button = tk.Button(self.login_window, text="Reset Password", command=lambda: self.handle_reset(self.forgot_email_entry.get()))
        login_button = tk.Button(self.login_window, text="Login", command=self.login_ui)

        reset_password_button.pack(pady=5)
        login_button.pack(side="bottom", pady=2)


    # Creates Email Template for OTP
    def handle_reset(self, email):
        results = self.db_manager.search_user(email)
        if results:
            otp = self.otp_manager.generate_otp()
            self.otp_manager.send_email(email, otp) 
            messagebox.showinfo("One Time Password Sent", "Please check your email for your OTP.")
            self.OTP_request_window(email)
        else:
            self.forgot_email_entry.config(highlightthickness=2, highlightbackground = "red", highlightcolor= "red")            
            messagebox.showwarning("Email Not Found", "Email hasn't been registered yet.")


    # Creates the OTP Request Window
    def OTP_request_window(self, email):
        for i in self.login_window.winfo_children():
            i.destroy()
        tk.Label(self.login_window, text="Email").pack()
        email_entry = tk.Entry(self.login_window, width=22)
        email_entry.pack(pady=3)
        email_entry.insert(0, email)

        tk.Label(self.login_window, text="Enter Your OTP").pack()
        OTP_entry = tk.Entry(self.login_window, width=22)
        OTP_entry.pack(pady=3)    

        self.submit_OTP = tk.Button(self.login_window, text="Submit", command=lambda: self.check_OTP(int(OTP_entry.get()), email))
        self.submit_OTP.pack(side= "bottom", pady=10)
        return


    # Handles the OTP Comparison
    def check_OTP(self, OTP, email):
        if self.otp_manager.verify_OTP(OTP):
            self.reset_password_window(email)
        else:
            messagebox.showerror("Wrong OTP", "Please Try Again.")


    # Creates Reset Password Window When OTP is Confirmed
    def reset_password_window(self, email):
        for i in self.login_window.winfo_children():
            i.destroy()

        self.login_window.title("Password Manager Reset Password")

        tk.Label(self.login_window, text=" Enter your Email:").pack()
        email_entry = tk.Entry(self.login_window, width=22)
        email_entry.pack(pady=3)

        email_entry.insert(0, email)
        email_entry.config(state="readonly")
        email_entry.config(readonlybackground="#201c1c")

        tk.Label(self.login_window, text="Enter your Password:").pack()
        password_entry = tk.Entry(self.login_window, show="*", width=22)
        password_entry.pack(pady=3)

        tk.Label(self.login_window, text="Confirm your Password:").pack()
        confirm_password_entry = tk.Entry(self.login_window, show="*", width=22)
        confirm_password_entry.pack(pady=3)

        submit_button = tk.Button(self.login_window, text="Log In",command=lambda: self.validate_user(email_entry, password_entry, confirm_password_entry, action="reset"))
        submit_button.pack(pady=5)

        self.login_window.bind("<Return>", lambda event:self.validate_user(email_entry, password_entry, confirm_password_entry, action="reset"))