import tkinter as tk
from ttkbootstrap import ttk
from tkinter import BOTTOM, messagebox

import ttkbootstrap as tb

from handlers.email_manager import EmailManager
from handlers.encryption_manager import EncryptionManager
from handlers.log_manager import LogManager
from handlers.otp_manager import OTPManager


class MasterLogin:
    def __init__(self, db_manager, login_success) -> None:
        """
        Manages the master login UI screen which verifies user data.
        """
        self.db_manager = db_manager
        self.log_manager = LogManager()
        self.encryption_manager = EncryptionManager(self.log_manager)
        self.email_manager = EmailManager(self.log_manager)
        self.otp_manager = OTPManager(self.email_manager, self.log_manager)

        self.login_window = tk.Tk()
        self.login_window.title("Password Manager")
        self.login_window.resizable(False, False)
        self.login_window.geometry("350x270+550+150")

        self.style = tb.Style()
        self.style.theme_use("cyborg")

        self.login_success = login_success

        self.current_frame = None
        self.user_id = None
        self.switch_mode("login")

        self.login_window.mainloop()

    def switch_mode(self, action="signup") -> None:
        """
        Switches UI mode dynamically.
        """
        if self.current_frame:
            self.current_frame.destroy()

        if action == "signup":
            self.signup_ui()
        elif action == "login":
            self.login_ui()
        elif action == "forgot_password":
            self.forgot_password()
        elif action == "otp_check":
            self.otp_check_ui()
        elif action == "reset_password":
            self.reset_password_ui()

    def create_label_entry(self, frame: ttk.Frame, label_text, show: str | None = None):
        """
        Creates and returns a label and entry widget pair.
        """
        ttk.Label(frame, text=label_text).pack()
        entry = ttk.Entry(frame, show=show if show is not None else "", width=22)
        entry.pack(pady=3)
        return entry

    def signup_ui(self) -> None:
        """
        Creates the sign-up UI widgets.
        """
        self.bottom_frame.forget()
        frame = ttk.Frame(self.login_window)
        frame.focus()
        frame.pack()
        self.current_frame = frame

        self.login_window.title("Password Manager Signup")

        email_entry = self.create_label_entry(frame, "Enter your Email:")
        password_entry = self.create_label_entry(
            frame, "Enter your Password:", show="*"
        )
        confirm_password_entry = self.create_label_entry(
            frame, "Confirm your Password:", show="*"
        )

        ttk.Button(
            frame,
            text="Register",
            command=lambda: self.validate_user(
                email_entry, password_entry, confirm_password_entry, action="new"
            ),
        ).pack(pady=3)
        ttk.Button(
            frame, text="Login", command=lambda: self.switch_mode("login")
        ).pack()

        frame.bind(
            "<Return>",
            lambda event: self.validate_user(
                email_entry, password_entry, confirm_password_entry, action="new"
            ),
        )

    def login_ui(self) -> None:
        """
        Creates login UI widgets.
        """
        frame = ttk.Frame(self.login_window)
        frame.focus()
        frame.pack()
        self.current_frame = frame

        self.login_window.title("Password Manager Login")

        email_entry = self.create_label_entry(frame, "Email")
        password_entry = self.create_label_entry(frame, "Password", show="*")
        ttk.Button(
            frame,
            text="Log In",
            command=lambda: self.credentials_check(email_entry, password_entry),
        ).pack(pady=5)

        self.bottom_frame = ttk.Frame(self.login_window)
        self.bottom_frame.pack(side=BOTTOM, pady=10)

        ttk.Button(
            self.bottom_frame,
            text="Sign Up",
            command=lambda: self.switch_mode("signup"),
        ).pack(pady=2)
        ttk.Button(
            self.bottom_frame,
            text="Forgot Password",
            command=lambda: self.switch_mode("forgot_password"),
        ).pack(pady=2)

        frame.bind(
            "<Return>",
            lambda event: self.credentials_check(email_entry, password_entry),
        )

    def validate_user(
        self,
        email_entry: ttk.Entry,
        password_entry: ttk.Entry,
        confirm_entry: ttk.Entry,
        action="new",
    ) -> None:
        """
        Validates user data.
        """
        email = email_entry.get()
        password = password_entry.get()
        confirm_password = confirm_entry.get()

        if not self.email_manager.is_valid_email(email):
            messagebox.showwarning(
                "Invalid Email", "Please enter a valid email address."
            )
            return

        if len(password) < 8:
            messagebox.showerror("Error", "Choose a stronger password.")
            return

        if password == confirm_password:
            handler = (
                self.new_user_handler if action == "new" else self.update_user_handler
            )
            handler(email, password)
        else:
            messagebox.showerror("Error", "Passwords do not match.")

    def credentials_check(
        self, email_entry: ttk.Entry, password_entry: ttk.Entry
    ) -> None:
        """
        Validates login credentials.
        """
        email = email_entry.get()
        password = password_entry.get()

        if not self.email_manager.is_valid_email(email):
            messagebox.showwarning(
                "Invalid Email", "Please enter a valid email address."
            )
            return

        results = self.db_manager.search_user(email)
        if not results:
            messagebox.showerror("Invalid Credentials", "Incorrect email or password.")
            return

        user_id, stored_salt, stored_hash = results
        if self.encryption_manager.hash_password(password, stored_salt) != stored_hash:
            messagebox.showerror("Invalid Credentials", "Incorrect email or password.")
            return

        self.db_manager.set_user_id(user_id)
        self.login_window.withdraw()
        self.login_success()

    def forgot_password(self) -> None:
        """
        Creates forgot password UI widgets.
        """
        self.bottom_frame.pack_forget()
        frame = ttk.Frame(self.login_window)
        frame.focus()
        frame.pack()
        self.current_frame = frame

        self.login_window.title("Reset Password")
        email_entry = self.create_label_entry(frame, "Enter your Email:")

        ttk.Button(
            frame,
            text="Reset Password",
            command=lambda: self.handle_reset(email_entry.get()),
        ).pack(pady=5)
        ttk.Button(
            frame, text="Login", command=lambda: self.switch_mode("login")
        ).pack()

        frame.bind("<Return>", lambda event: self.handle_reset(email_entry.get()))

    def handle_reset(self, email: str) -> None:
        """
        Handles OTP generation and sends via email.
        """
        user = self.db_manager.search_user(email)
        self.email = email
        if user:
            self.user_id = user[0]
            otp = self.otp_manager.generate_otp()
            self.email_manager.send_email(
                email, file_path="./templates/otp_template.html", otp=otp
            )
            messagebox.showinfo("OTP Sent", "Please check your email.")
            self.switch_mode("otp_check")
        else:
            messagebox.showwarning(
                "Email Not Found", "Email hasn't been registered yet."
            )

    def otp_check_ui(self) -> None:
        """
        Creates OTP check UI widgets.
        """
        self.bottom_frame.pack_forget()
        frame = ttk.Frame(self.login_window)
        frame.focus()
        frame.pack()
        self.current_frame = frame

        self.login_window.title("Enter OTP")
        otp_entry = self.create_label_entry(frame, "Enter OTP:")

        ttk.Button(
            frame,
            text="Verify OTP",
            command=lambda: self.verify_user_otp(otp_entry.get()),
        ).pack(pady=5)
        ttk.Button(
            frame, text="Login", command=lambda: self.switch_mode("login")
        ).pack()

        frame.bind("<Return>", lambda event: self.verify_user_otp(otp_entry.get()))

    def verify_user_otp(self, otp: str) -> None:
        """
        Verifies the entered OTP.
        """
        if self.otp_manager.verify_otp(int(otp)):
            self.log_manager.log("Info", f"Successful OTP Check for: {self.email}")
            self.switch_mode("reset_password")
        else:
            messagebox.showerror(
                "Invalid OTP", "The OTP you entered is incorrect. Please try again."
            )

    def reset_password_ui(self) -> None:
        """
        Creates the password reset UI widgets.
        """
        self.bottom_frame.pack_forget()
        frame = ttk.Frame(self.login_window)
        frame.focus()
        frame.pack()
        self.current_frame = frame

        self.login_window.title("Reset Password")

        password_entry = self.create_label_entry(frame, "Enter New Password:", show="*")
        confirm_password_entry = self.create_label_entry(
            frame, "Confirm New Password:", show="*"
        )

        ttk.Button(
            frame,
            text="Reset Password",
            command=lambda: self.reset_password(password_entry, confirm_password_entry),
        ).pack(pady=5)
        ttk.Button(
            frame, text="Login", command=lambda: self.switch_mode("login")
        ).pack()

        frame.bind(
            "<Return>",
            lambda event: self.reset_password(password_entry, confirm_password_entry),
        )

    def reset_password(
        self, password_entry: ttk.Entry, confirm_password_entry: ttk.Entry
    ) -> None:
        """
        Handles the password reset process.
        """
        password = password_entry.get()
        confirm_password = confirm_password_entry.get()

        if len(password) < 8:
            messagebox.showerror("Error ", "Choose a stronger password.")
            return

        if password == confirm_password:
            email = self.db_manager.get_email(self.user_id)[0]
            salt = self.encryption_manager.generate_salt()
            hash = self.encryption_manager.hash_password(password, salt)
            self.db_manager.update_user(email, hash, salt)
            messagebox.showinfo("Success", "Password reset successfully.")
            self.switch_mode("login")
        else:
            messagebox.showerror("Error", "Passwords do not match.")

    def new_user_handler(self, email: str, password: str) -> None:
        """
        Handles new user registration & Sends Formatted Email with User's Username.
        """
        salt = self.encryption_manager.generate_salt()
        hash = self.encryption_manager.hash_password(password, salt)
        try:
            self.db_manager.create_new_user(email, hash, salt)
            self.switch_mode("login")
            self.email_manager.send_email(email, file_path="./templates/welcome.html")

        except Exception as e:
            self.log_manager.log("Error", f"Failed to create Account: {e}")

    def update_user_handler(self, email: str, password: str) -> None:
        """
        Handles updating user password & Sends Formatted Email with User's Username.
        """
        salt = self.encryption_manager.generate_salt()
        hash = self.encryption_manager.hash_password(password, salt)
        self.db_manager.update_user(email, hash, salt)
        self.switch_mode("login")
        self.email_manager.send_email(
            email, file_path="./templates/update_account.html"
        )
