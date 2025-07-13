import customtkinter as ctk
from threading import Thread
from tkinter import BOTTOM, messagebox, font

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
        self.login_window.geometry("570x540+550+150")

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.login_success = login_success

        self.current_frame = None
        self.user_id = None
        self.switch_mode("login")

        self.login_window.mainloop()

    def switch_mode(self, action: str = "signup") -> None:
        """
        Switches UI mode dynamically.
        Args:
            action (str): The action to perform. One of "signup", "login", "forgot_password", "otp_check", "reset_password".
        Returns:
            None
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
        self, frame: ctk.CTkFrame, label_text: str, show: str | None = None
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
        ctk.CTkLabel(
            frame, text=label_text, font=("Arial", 25), width=200, height=43
        ).pack(pady=10)
        entry = ctk.CTkEntry(
            frame,
            show=show if show is not None else "",
            width=225,
            height=43,
            font=("Arial", 25),
            bg_color="#242424",
            fg_color="#242424",
        )
        entry.pack(pady=2)
        return entry

    def signup_ui(self) -> None:
        """
        Creates the sign-up UI widgets.
        Returns:
            None
        """
        for widget in self.login_window.winfo_children():
            widget.destroy()

        frame = ctk.CTkFrame(self.login_window, fg_color="#242424")
        frame.focus()
        frame.pack()
        self.current_frame = frame

        self.login_window.title("Password Manager Signup")

        def register_user():
            self.validate_user(
                email_entry, password_entry, confirm_password_entry, action="new"
            )

        email_entry = self.create_label_entry(frame, "Enter your Email:")
        password_entry = self.create_label_entry(
            frame, "Enter your Password:", show="*"
        )
        confirm_password_entry = self.create_label_entry(
            frame, "Confirm your Password:", show="*"
        )

        bottom_frame = ctk.CTkFrame(self.login_window, fg_color="#242424")
        bottom_frame.pack(side="bottom", fill="x", pady=10)

        ctk.CTkButton(
            frame,
            text="Register",
            command=register_user,
            width=170,
            height=43,
            font=("Arial", 25),
        ).pack(pady=10)

        ctk.CTkButton(
            bottom_frame,
            text="Generate Password",
            width=205,
            height=43,
            font=("Arial", 25),
            command=lambda: self.password_generator.generate_window(),
        ).pack(pady=2, side=ctk.BOTTOM)

        ctk.CTkButton(
            bottom_frame,
            text="Login",
            width=235,
            height=43,
            command=lambda: self.switch_mode("login"),
            font=("Arial", 25),
        ).pack(pady=5, side=ctk.BOTTOM)

        frame.bind("<Return>", lambda event: register_user())

    def login_ui(self) -> None:
        """
        Creates login UI widgets.
        Returns:
            None
        """
        for widget in self.login_window.winfo_children():
            widget.destroy()

        frame = ctk.CTkFrame(
            self.login_window,
            bg_color="#242424",
            fg_color="#242424",
        )
        frame.focus()
        frame.pack()
        self.current_frame = frame

        self.login_window.title("Password Manager Login")

        email_entry = self.create_label_entry(frame, "Email")
        password_entry = self.create_label_entry(frame, "Password", show="*")
        email_entry.focus()

        self.login_button = ctk.CTkButton(
            frame,
            text="Log In",
            width=170,
            height=43,
            font=("Arial", 25),
            command=lambda: self.credentials_check(email_entry, password_entry),
        )
        self.login_button.pack(pady=15)

        bottom_frame = ctk.CTkFrame(self.login_window, fg_color="#242424")
        bottom_frame.pack(side=BOTTOM, pady=10)

        ctk.CTkButton(
            bottom_frame,
            text="Sign Up",
            width=205,
            height=43,
            font=("Arial", 25),
            command=lambda: self.switch_mode("signup"),
        ).pack(pady=2)

        ctk.CTkButton(
            bottom_frame,
            text="Forgot Password",
            width=170,
            height=43,
            font=("Arial", 25),
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
        action: str = "new",
    ) -> None:
        """
        Validates user data with optimized checks.
        Args:
            email_entry (ctk.CTkEntry): The email entry widget.
            password_entry (ctk.CTkEntry): The password entry widget.
            confirm_entry (ctk.CTkEntry): The confirm password entry widget.
            action (str): The action to perform. Defaults to "new".
        Returns:
            None
        """
        email = email_entry.get().strip()
        password = password_entry.get()
        confirm_password = confirm_entry.get()

        if not email or not password or not confirm_password:
            messagebox.showerror("Error", "All fields are required")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return

        if len(password) < 8:
            messagebox.showerror(
                "Error", "Choose a stronger password (min 8 characters)"
            )
            return

        if not self.email_manager.is_valid_email(email):
            messagebox.showwarning(
                "Invalid Email", "Please enter a valid email address"
            )
            return
        handler = self.new_user_handler if action == "new" else self.update_user_handler
        handler(email, password)

    def credentials_check(
        self, email_entry: ctk.CTkEntry, password_entry: ctk.CTkEntry
    ) -> None:
        """
        Validates login credentials asynchronously.
        Args:
            email_entry (ctk.CTkEntry): The email entry widget.
            password_entry (ctk.CTkEntry): The password entry widget.
        Returns:
            None
        """
        email = email_entry.get()
        password = password_entry.get()
        if not self.email_manager.is_valid_email(email):
            messagebox.showwarning(
                "Invalid Email", "Please enter a valid email address."
            )
            return

        self.login_button.configure(state="disabled", text="Checking...")

        def check_credentials_thread():
            try:
                results = self.database_manager.search_user(email)
                if not results:
                    self.login_window.after(
                        0,
                        lambda: messagebox.showerror(
                            "Invalid Credentials", "Incorrect email or password."
                        ),
                    )
                    self.login_window.after(
                        0,
                        lambda: self.login_button.configure(
                            state="normal", text="Log In"
                        ),
                    )
                    return
                user_id, stored_hash = results

                def on_verification_complete(is_valid):
                    if is_valid:
                        if user_id is not None:
                            self.database_manager.set_user_id(user_id)
                            self.user_id = user_id
                        else:
                            raise ValueError("User ID cannot be None")
                        self.login_window.withdraw()
                        self.login_success()
                    else:
                        self.login_window.after(
                            0,
                            lambda: messagebox.showerror(
                                "Invalid Credentials", "Incorrect email or password."
                            ),
                        )
                        self.login_window.after(
                            0,
                            lambda: self.login_button.configure(
                                state="normal", text="Log In"
                            ),
                        )

                is_valid = self.encryption_manager.verify_password(
                    password, stored_hash
                )
                self.login_window.after(0, lambda: on_verification_complete(is_valid))

            except Exception as e:
                self.log_manager.log("Error", f"Login error: {e}")
                self.login_window.after(
                    0, lambda: messagebox.showerror("Error", f"Login failed: {str(e)}")
                )
                self.login_window.after(
                    0,
                    lambda: self.login_button.configure(state="normal", text="Log In"),
                )

        Thread(target=check_credentials_thread, daemon=True).start()

    def forgot_password(self) -> None:
        """
        Creates forgot password UI widgets.
        Returns:
            None
        """
        for widget in self.login_window.winfo_children():
            widget.destroy()

        frame = ctk.CTkFrame(self.login_window, fg_color="#242424")
        frame.focus()
        frame.pack()
        self.current_frame = frame

        self.login_window.title("Reset Password")
        email_entry = self.create_label_entry(frame, "Enter your Email:")

        ctk.CTkButton(
            frame,
            text="Reset Password",
            width=170,
            height=43,
            font=("Arial", 25),
            command=lambda: self.handle_reset(email_entry.get()),
        ).pack(pady=15)

        bottom_frame = ctk.CTkFrame(self.login_window, fg_color="#242424")
        bottom_frame.pack(side="bottom", fill="x", pady=10)

        ctk.CTkButton(
            bottom_frame,
            text="Login",
            width=170,
            height=43,
            font=("Arial", 25),
            command=lambda: self.switch_mode("login"),
        ).pack()

        frame.bind("<Return>", lambda event: self.handle_reset(email_entry.get()))

    def otp_check_ui(self) -> None:
        """
        Creates OTP check UI widgets.
        Returns:
            None
        """
        for widget in self.login_window.winfo_children():
            widget.destroy()

        frame = ctk.CTkFrame(self.login_window, fg_color="#242424")
        frame.focus()
        frame.pack()
        self.current_frame = frame

        self.login_window.title("Enter OTP")
        otp_entry = self.create_label_entry(frame, "Enter OTP:")

        ctk.CTkButton(
            frame,
            text="Verify OTP",
            font=("Arial", 25),
            command=lambda: self.verify_user_otp(otp_entry.get()),
        ).pack(pady=5)
        ctk.CTkButton(
            frame,
            text="Login",
            command=lambda: self.switch_mode("login"),
            font=("Arial", 25),
        ).pack()
        frame.bind("<Return>", lambda event: self.verify_user_otp(otp_entry.get()))

    def verify_user_otp(self, otp: str, event=None) -> None:
        """
        Verifies the entered OTP.
        Args:
            otp (str): The OTP entered by the user.
        """
        if self.otp_manager.verify_otp(int(otp)):
            self.log_manager.log("info", f"Successful OTP Check for: {self.email}")
            self.switch_mode("reset_password")
        else:
            messagebox.showerror(
                "Invalid OTP", "The OTP you entered is incorrect. Please try again."
            )

    def reset_password_ui(self) -> None:
        """
        Creates the password reset UI widgets.
        Returns:
            None
        """
        frame = ctk.CTkFrame(self.login_window, fg_color="#242424")
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
            font=("Arial", 25),
            command=lambda: self.reset_password(password_entry, confirm_password_entry),
        ).pack(pady=5)

        ctk.CTkButton(
            frame,
            text="Login",
            font=("Arial", 25),
            command=lambda: self.switch_mode("login"),
        ).pack()

        ctk.CTkButton(
            frame,
            text="Generate Password",
            font=("Arial", 25),
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
        self,
        password_entry: ctk.CTkEntry,
        confirm_password_entry: ctk.CTkEntry,
        event=None,
    ) -> None:
        """
        Handles the password reset process.
        Args:
            password_entry (ctk.CTkEntry): The password entry widget.
            confirm_password_entry (ctk.CTkEntry): The confirm password entry widget.
        Returns:
            None
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
                password_hash = self.encryption_manager.hash_password(password)
                self.database_manager.update_user(email, password_hash)
            messagebox.showinfo("Success", "Password reset successfully.")
            self.switch_mode("login")
        else:
            messagebox.showerror("Error", "Passwords do not match.")

    def new_user_handler(self, email: str, password: str) -> None:
        """
        Optimized handler for new user registration.
        Args:
            email (str): The user's email.
            password (str): The user's password.
        Returns:
            None
        """
        try:
            password_hash = self.encryption_manager.hash_password(password)

            self.database_manager.create_new_user(email, password_hash)
            messagebox.showinfo("Success", "Account created successfully!")

            self.switch_mode("login")
            self.email_manager.send_email(email, file_path="./templates/welcome.html")

        except Exception as e:
            self.log_manager.log("Error", f"Failed to create Account: {e}")
            messagebox.showerror(
                "Error", f"Failed to create account. Please try again."
            )

    def update_user_handler(self, email: str, password: str) -> None:
        """
        Handles updating user password & Sends Formatted Email with User's Username.
        Args:
            email (str): The user's email.
            password (str): The user's password.
        Returns:
            None
        """
        password_hash = self.encryption_manager.hash_password(password)
        self.database_manager.update_user(email, password_hash)
        self.switch_mode("login")
        self.email_manager.send_email(
            email, file_path="./templates/update_account.html"
        )
