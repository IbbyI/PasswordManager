import tkinter as tk
import ttkbootstrap as tb
from tkinter import messagebox
from handlers.encryption_manager import EncryptionManager
from handlers.email_manager import EmailManager
from handlers.otp_manager import OTPManager
from handlers.log_manager import LogManager


class MasterLogin:
    def __init__(self, db_manager, login_success) -> None:
        """
        Manages the master login ui screen which verifies user data.
        """
        self.db_manager = db_manager
        self.log_manager = LogManager()
        self.encryption_manager = EncryptionManager(self.log_manager)
        self.email_manager = EmailManager(self.log_manager)
        self.otp_manager = OTPManager(self.email_manager, self.log_manager)

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

    def mode(self, action="signup") -> None:
        """
        Changes the ui depending on the mode.
        """
        if action == "signup":
            self.signup_ui()
        if action == "login":
            self.login_ui()
        if action == "forgot_password":
            self.forgot_password()

    def signup_ui(self) -> None:
        """
        Creates the sign-up ui wigits, retrieves and validates data.
        """
        for i in self.login_window.winfo_children():
            i.destroy()

        self.login_window.title("Password Manager Signup")

        tk.Label(
            self.login_window,
            text=" Enter your Email:",
        ).pack()
        email_entry = tk.Entry(self.login_window, width=22)
        email_entry.pack(pady=3)

        tk.Label(
            self.login_window,
            text="Enter your Password:",
        ).pack()
        password_entry = tk.Entry(self.login_window, show="*", width=22)
        password_entry.pack(pady=3)

        tk.Label(
            self.login_window,
            text="Confirm your Password:",
        ).pack()
        confirm_password_entry = tk.Entry(
            self.login_window,
            show="*",
            width=22
        )
        confirm_password_entry.pack(pady=3)

        self.register_button = tk.Button(
            self.login_window,
            text="Register",
            command=lambda:
                self.validate_user(
                    email_entry,
                    password_entry,
                    confirm_password_entry,
                    action="new"),
        )
        login = tk.Button(
            self.login_window,
            text="Login",
            command=self.login_ui)

        self.register_button.pack(pady=3)
        login.pack(anchor="center", side="bottom", pady=2)

        self.login_window.bind(
            "<Return>",
            lambda event:
                self.validate_user(
                    email_entry,
                    password_entry,
                    confirm_password_entry,
                    action="new"),
        )

    def login_ui(self) -> None:
        """
        Creates login ui wigits, retrieves and validates data.
        """
        for i in self.login_window.winfo_children():
            i.destroy()

        self.login_window.title("Password Manager Login")

        tk.Label(self.login_window, text="Email").pack()
        email_entry = tk.Entry(self.login_window, width=22)
        email_entry.pack(pady=3)

        tk.Label(self.login_window, text="Password").pack()
        password_entry = tk.Entry(self.login_window, show="*", width=22)
        password_entry.pack(pady=3)

        login_button = tk.Button(
            self.login_window,
            text="Log In",
            command=lambda:
                self.credentials_check(
                    email_entry,
                    password_entry,
                ))
        forgot_password = tk.Button(
            self.login_window, text="Forgot Password", command=lambda: self.forgot_password())
        signup = tk.Button(
            self.login_window,
            text="Sign Up",
            command=self.signup_ui,
        )

        login_button.pack(pady=5)
        forgot_password.pack(side="bottom", anchor="center", pady=3)
        signup.pack(side="bottom", anchor="center")

        self.login_window.bind(
            "<Return>",
            lambda event:
                self.credentials_check(
                    email_entry,
                    password_entry,
                ))

    def validate_user(
        self,
        email_entry: tk.Entry,
        password_entry: tk.Entry,
        confirm_entry: tk.Entry,
        action="new"
    ) -> None:
        """
        Validates user data.
        """
        if not self.email_manager.is_valid_email(email_entry.get()):
            messagebox.showwarning(
                "Invalid Email",
                "Please enter a valid email address.",
            )
            email_entry.config(
                highlightthickness=2,
                highlightbackground="red",
                highlightcolor="red",
            )
            return

        if len(password_entry.get()) < 8 or self.email_manager.strength(password_entry.get()) is True:
            password_entry.config(
                highlightthickness=2,
                highlightbackground="red",
                highlightcolor="red"
            )
            messagebox.showerror(
                "Error",
                "Choose a Stronger Password")
            return

        if password_entry.get() == confirm_entry.get():
            if action == "new":
                self.new_user_handler(
                    email_entry.get(),
                    password_entry.get())
            if action == "reset":
                self.update_user_handler(
                    email_entry.get(),
                    password_entry.get())
        else:
            password_entry.config(
                highlightthickness=2,
                highlightbackground="red",
                highlightcolor="red",
            )
            confirm_entry.config(
                highlightthickness=2,
                highlightbackground="red",
                highlightcolor="red",
            )
            messagebox.showerror(
                "Error",
                "Passwords do not match.")

    def credentials_check(
            self,
            email_entry: tk.Entry,
            password_entry: tk.Entry,
    ) -> None:
        """
        Searches database for given credentials and validates it.
        """
        email = email_entry.get()
        password = password_entry.get()
        if not self.email_manager.is_valid_email(email):
            email_entry.config(
                highlightthickness=2,
                highlightbackground="red",
                highlightcolor="red",
            )
            messagebox.showwarning(
                "Invalid Email",
                "Please enter a valid email address.",
            )
            return

        results = self.db_manager.search_user(email)
        if results:
            user_id = results[0]
        else:
            email_entry.config(
                highlightthickness=2,
                highlightbackground="red",
                highlightcolor="red",
            )
            password_entry.config(
                highlightthickness=2,
                highlightbackground="red",
                highlightcolor="red",
            )
            messagebox.showerror(
                "Invalid Credentials",
                "The username and password you entered do not match our records.",
            )
            return

        hash = self.encryption_manager.hash_password(
            password,
            results[1],
            iterations=10000,
        )
        if hash != results[2]:
            email_entry.config(
                highlightthickness=2,
                highlightbackground="red",
                highlightcolor="red",
            )
            password_entry.config(
                highlightthickness=2,
                highlightbackground="red",
                highlightcolor="red",
            )
            messagebox.showerror(
                "Invalid Credentials",
                "The username and password you entered do not match our records.",
            )
            return
        else:
            self.db_manager.set_user_id(user_id)
            self.login_window.withdraw()
            self.login_success()

    def new_user_handler(self, email: str, password: str) -> None:
        """
        Handles salt, hashing, email notification and user creation when signing up.
        """
        try:
            salt = self.encryption_manager.generate_salt()
            hash = self.encryption_manager.hash_password(password, salt)
            self.db_manager.create_new_user(email, hash, salt)
            self.login_ui()
            self.email_manager.send_email(email, file="./html/welcome.html")
        except self.db_manager.sqlite3.IntegrityError:
            messagebox.showerror(
                "Account Already Exists",
                "The email you entered is already registered.\nPlease log in or use the \"Forgot Password\" option to recover your account."
            )
            self.log_manager.write_log(f"Account Already Exists: {email}")

    def update_user_handler(self, email: str, password: str) -> None:
        """
        Handles salt, hashing, email notification and updating user data.
        """
        salt = self.encryption_manager.generate_salt()
        hash = self.encryption_manager.hash_password(password, salt)
        self.db_manager.update_user(email, hash, salt)
        self.login_ui()
        self.email_manager.send_email(email, file="./html/edit_data.html")

    def forgot_password(self) -> None:
        """
        Creates forgot password wigits
        """
        for i in self.login_window.winfo_children():
            i.destroy()

        self.login_window.title("Reset Password")

        tk.Label(self.login_window, text=" Enter your Email:").pack()
        self.forgot_email_entry = tk.Entry(self.login_window, width=22)
        self.forgot_email_entry.pack(pady=3)

        reset_password_button = tk.Button(
            self.login_window, text="Reset Password",
            command=lambda: self.handle_reset(self.forgot_email_entry.get()))
        login_button = tk.Button(
            self.login_window, text="Login", command=self.login_ui)

        reset_password_button.pack(pady=5)
        login_button.pack(side="bottom", pady=2)

    def handle_reset(self, email: str) -> None:
        """
        Handles OTP generation and sends via email.
        """
        results = self.db_manager.search_user(email)
        if results:
            otp = self.otp_manager.generate_otp()
            self.otp_manager.send_email(email)
            messagebox.showinfo(
                "One Time Password Sent",
                "Please check your email for your OTP.",
            )
            self.OTP_request_window(email)
        else:
            self.forgot_email_entry.config(
                highlightthickness=2,
                highlightbackground="red",
                highlightcolor="red",
            )
            messagebox.showwarning(
                "Email Not Found",
                "Email hasn't been registered yet.",
            )

    def OTP_request_window(self, email: str) -> None:
        """
        Creates OTP request ui wigits and submits data.
        """
        for i in self.login_window.winfo_children():
            i.destroy()
        tk.Label(self.login_window, text="Email").pack()
        email_entry = tk.Entry(self.login_window, width=22)
        email_entry.pack(pady=3)
        email_entry.insert(0, email)

        tk.Label(self.login_window, text="Enter Your OTP").pack()
        OTP_entry = tk.Entry(self.login_window, width=22)
        OTP_entry.pack(pady=3)

        self.submit_OTP = tk.Button(
            self.login_window, text="Submit",
            command=lambda:
                self.check_OTP(int(OTP_entry.get()), email))
        self.submit_OTP.pack(side="bottom", pady=10)
        return

    def check_OTP(self, OTP: int, email: str) -> None:
        """
        Handles ui changes after OTP verification.
        """
        if self.otp_manager.verify_otp(OTP):
            self.reset_password_window(email)
        else:
            messagebox.showerror("Wrong OTP", "Please Try Again.")

    def reset_password_window(self, email: str) -> None:
        """
        Creates reset password ui wigits after otp verification.
        """
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
        confirm_password_entry = tk.Entry(
            self.login_window, show="*", width=22)
        confirm_password_entry.pack(pady=3)

        submit_button = tk.Button(self.login_window, text="Log In",
                                  command=lambda:
                                  self.validate_user(
                                      email_entry,
                                      password_entry,
                                      confirm_password_entry,
                                      action="reset"))
        submit_button.pack(pady=5)

        self.login_window.bind("<Return>",
                               lambda event:
                               self.validate_user(
                                   email_entry,
                                   password_entry,
                                   confirm_password_entry,
                                   action="reset"))
