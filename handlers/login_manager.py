import customtkinter as ctk
from tkinter import BOTTOM, messagebox

from handlers.database_manager import DatabaseManager
from handlers.email_manager import EmailManager
from handlers.encryption_manager import EncryptionManager
from handlers.log_manager import LogManager
from handlers.otp_manager import OTPManager
from handlers.password_generator import PasswordGenerator


class LoginManager:
    """
    Manages the master login UI screen which verifies user data.
    """

    def __init__(self, database_manager: DatabaseManager, login_success) -> None:
        """
        Initialize the LoginManager with dependencies.
        Args:
            database_manager: The database manager object.
            login_success: The function to call when login is successful.
        """
        self.database_manager = database_manager
        self.log_manager = LogManager()
        self.password_generator = PasswordGenerator()
        self.encryption_manager = EncryptionManager(self.log_manager)
        self.email_manager = EmailManager(self.log_manager)
        self.otp_manager = OTPManager(self.email_manager, self.log_manager)

        self.login_window = ctk.CTk()
        self.login_window.title("Password Manager")
        self.login_window.resizable(False, False)
        self.login_window.geometry("350x270+550+150")

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.login_success = login_success

        self.current_frame = None
        self.user_id = None
        self.switch_mode("login")

        self.login_window.mainloop()

    def switch_mode(self, action="signup") -> None:
        """
        Switches UI mode dynamically.
        Args:
            action (str): The action to perform.
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

    def create_label_entry(
        self, frame: ctk.CTkFrame, label_text, show: str | None = None
    ) -> ctk.CTkEntry:
        """
        Creates and returns a label and entry widget pair.
        Args:
            frame (ctk.CTkFrame): The frame to place the widgets in.
            label_text (str): The text to display on the label.
            show (str | None): The character to show in the entry widget. Defaults to None.
        Returns:
            ctk.CTkEntry: The entry widget created.
        """
        ctk.CTkLabel(frame, text=label_text).pack()
        entry = ctk.CTkEntry(
            frame,
            show=show if show is not None else "",
            width=150,
            bg_color="#242525",
            fg_color="#242525",
        )
        entry.pack(pady=3)
        return entry

    def signup_ui(self) -> None:
        """
        Creates the sign-up UI widgets.
        """
        self.bottom_frame.forget()
        frame = ctk.CTkFrame(self.login_window, fg_color="#242525")
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

        ctk.CTkButton(
            frame,
            text="Register",
            command=lambda: self.validate_user(
                email_entry, password_entry, confirm_password_entry, action="new"
            ),
        ).pack(pady=3)
        ctk.CTkButton(
            frame, text="Login", command=lambda: self.switch_mode("login")
        ).pack(side=ctk.BOTTOM)

        ctk.CTkButton(
            frame,
            text="Generate Password",
            command=lambda: self.password_generator.generate_window(),
        ).pack(side=ctk.BOTTOM)

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
        frame = ctk.CTkFrame(
            self.login_window,
            bg_color="#242525",
            fg_color="#242525",
        )
        frame.focus()
        frame.pack()
        self.current_frame = frame

        self.login_window.title("Password Manager Login")

        email_entry = self.create_label_entry(frame, "Email")
        password_entry = self.create_label_entry(frame, "Password", show="*")
        email_entry.insert(0, "ibbyissa001@gmail.com")
        password_entry.insert(0, "Password12@")
        ctk.CTkButton(
            frame,
            text="Log In",
            command=lambda: self.credentials_check(email_entry, password_entry),
        ).pack(pady=5)

        self.bottom_frame = ctk.CTkFrame(self.login_window, fg_color="#242525")
        self.bottom_frame.pack(side=BOTTOM, pady=10)

        ctk.CTkButton(
            self.bottom_frame,
            text="Sign Up",
            command=lambda: self.switch_mode("signup"),
        ).pack(pady=2)
        ctk.CTkButton(
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
        email_entry: ctk.CTkEntry,
        password_entry: ctk.CTkEntry,
        confirm_entry: ctk.CTkEntry,
        action="new",
    ) -> None:
        """
        Validates user data.
        Args:
            email_entry (ctk.CTkEntry): The email entry widget.
            password_entry (ctk.CTkEntry): The password entry widget.
            confirm_entry (ctk.CTkEntry): The confirm password entry widget.
            action (str): The action to perform. Defaults to "new".
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
        self, email_entry: ctk.CTkEntry, password_entry: ctk.CTkEntry
    ) -> None:
        """
        Validates login credentials.
        Args:
            email_entry (ctk.CTkEntry): The email entry widget.
            password_entry (ctk.CTkEntry): The password entry widget.
        """
        email = email_entry.get()
        password = password_entry.get()

        if not self.email_manager.is_valid_email(email):
            messagebox.showwarning(
                "Invalid Email", "Please enter a valid email address."
            )
            return

        results = self.database_manager.search_user(email)
        if not results:
            messagebox.showerror("Invalid Credentials", "Incorrect email or password.")
            return

        user_id, stored_salt, stored_hash = results
        if self.encryption_manager.hash_password(password, stored_salt) != stored_hash:
            messagebox.showerror("Invalid Credentials", "Incorrect email or password.")
            return

        self.database_manager.set_user_id(user_id)
        self.login_window.withdraw()
        self.login_success()

    def forgot_password(self) -> None:
        """
        Creates forgot password UI widgets.
        """
        self.bottom_frame.pack_forget()
        frame = ctk.CTkFrame(self.login_window, fg_color="#242525")
        frame.focus()
        frame.pack()
        self.current_frame = frame

        self.login_window.title("Reset Password")
        email_entry = self.create_label_entry(frame, "Enter your Email:")

        ctk.CTkButton(
            frame,
            text="Reset Password",
            command=lambda: self.handle_reset(email_entry.get()),
        ).pack(pady=5)
        ctk.CTkButton(
            frame, text="Login", command=lambda: self.switch_mode("login")
        ).pack()

        frame.bind("<Return>", self.handle_reset(email_entry.get()))

    def otp_check_ui(self) -> None:
        """
        Creates OTP check UI widgets.
        """
        self.bottom_frame.pack_forget()
        frame = ctk.CTkFrame(self.login_window, fg_color="#242525")
        frame.focus()
        frame.pack()
        self.current_frame = frame

        self.login_window.title("Enter OTP")
        otp_entry = self.create_label_entry(frame, "Enter OTP:")

        ctk.CTkButton(
            frame,
            text="Verify OTP",
            command=lambda: self.verify_user_otp(otp_entry.get()),
        ).pack(pady=5)
        ctk.CTkButton(
            frame, text="Login", command=lambda: self.switch_mode("login")
        ).pack()

        frame.bind("<Return>", self.verify_user_otp(otp_entry.get()))

    def verify_user_otp(self, otp: str, event=None) -> None:
        """
        Verifies the entered OTP.
        Args:
            otp (str): The OTP entered by the user.
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
        frame = ctk.CTkFrame(self.login_window, fg_color="#242525")
        frame.focus()
        frame.pack()
        self.current_frame = frame

        self.login_window.title("Reset Password")

        password_entry = self.create_label_entry(frame, "Enter New Password:", show="*")
        confirm_password_entry = self.create_label_entry(
            frame, "Confirm New Password:", show="*"
        )
        ctk.CTkButton(
            frame,
            text="Reset Password",
            command=lambda: self.reset_password(password_entry, confirm_password_entry),
        ).pack(pady=5)

        ctk.CTkButton(
            frame, text="Login", command=lambda: self.switch_mode("login")
        ).pack()

        ctk.CTkButton(
            frame,
            text="Generate Password",
            command=lambda: self.password_generator.generate_window(),
        ).pack()

        frame.bind(
            "<Return>",
            lambda event: self.reset_password(password_entry, confirm_password_entry),
        )

    def handle_reset(self, email: str, event=None) -> None:
        """
        Handles OTP generation and sends via email.
        Args:
            email (str): The user's email.
        """
        if not email:
            messagebox.showwarning("Email Required", "Please enter your email.")
            return
        user = self.database_manager.search_user(email)
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

    def reset_password(
        self, password_entry: ctk.CTkEntry, confirm_password_entry: ctk.CTkEntry
    ) -> None:
        """
        Handles the password reset process.
        Args:
            password_entry (ctk.CTkEntry): The password entry widget.
            confirm_password_entry (ctk.CTkEntry): The confirm password entry widget.
        """
        password = password_entry.get()
        confirm_password = confirm_password_entry.get()

        if len(password) < 8:
            messagebox.showerror("Error ", "Choose a stronger password.")
            return

        if self.user_id is None:
            messagebox.showerror("Error", "User is not authenticated.")
            return

        if password == confirm_password:
            email_tuple = self.database_manager.get_email(self.user_id)
            if email_tuple:
                email = email_tuple[0]
            salt = self.encryption_manager.generate_salt()
            hash = self.encryption_manager.hash_password(password, salt)
            self.database_manager.update_user(email, hash, salt)
            messagebox.showinfo("Success", "Password reset successfully.")
            self.switch_mode("login")
        else:
            messagebox.showerror("Error", "Passwords do not match.")

    def new_user_handler(self, email: str, password: str) -> None:
        """
        Handles new user registration & Sends Formatted Email with User's Username.
        Args:
            email (str): The user's email.
            password (str): The user's password.
        """
        salt = self.encryption_manager.generate_salt()
        hash = self.encryption_manager.hash_password(password, salt)
        try:
            self.database_manager.create_new_user(email, hash, salt)
            self.switch_mode("login")
            self.email_manager.send_email(email, file_path="./templates/welcome.html")

        except Exception as e:
            self.log_manager.log("Error", f"Failed to create Account: {e}")

    def update_user_handler(self, email: str, password: str) -> None:
        """
        Handles updating user password & Sends Formatted Email with User's Username.
        Args:
            email (str): The user's email.
            password (str): The user's password.
        """
        salt = self.encryption_manager.generate_salt()
        hash = self.encryption_manager.hash_password(password, salt)
        self.database_manager.update_user(email, hash, salt)
        self.switch_mode("login")
        self.email_manager.send_email(
            email, file_path="./templates/update_account.html"
        )
