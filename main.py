import tkinter as tk

from handlers.account_manager import AccountManager
from handlers.database_manager import DatabaseManager
from handlers.email_manager import EmailManager
from handlers.encryption_manager import EncryptionManager
from handlers.gui_manager import GUIManager
from handlers.log_manager import LogManager
from handlers.login_manager import MasterLogin
from handlers.otp_manager import OTPManager
from handlers.password_generator import PasswordGenerator


class PasswordManagerApp:
    def __init__(self) -> None:
        """
        Initializes the PasswordManagerApp instance.
        - Sets up the logging manager (log_manager) to handle application logs.
        - Initializes the database manager (db_manager), passing the log manager for error reporting and logging.
        - Creates an instance of MasterLogin to manage user authentication, providing a callback (on_login_success)
        to handle successful logins.
        """
        self.log_manager = LogManager()
        self.db_manager = DatabaseManager(self.log_manager)
        self.master_login = MasterLogin(self.db_manager, self.on_login_success)
        self.main_window = None

    def on_login_success(self) -> None:
        """
        Initialize Main Tkinter Window With Necessary Classes
        """
        self.main_window = tk.Toplevel()
        self.main_window.title("Password Manager")
        self.main_window.resizable(False, False)

        self.email_manager = EmailManager(self.log_manager)
        self.encryption_manager = EncryptionManager(self.log_manager)
        self.otp_manager = OTPManager(self.email_manager, self.log_manager)
        self.password_generator = PasswordGenerator(self.main_window)
        self.ui_manager = GUIManager(self.main_window, self.db_manager)
        self.account_manager = AccountManager(
            self.main_window,
            self.db_manager,
            self.encryption_manager,
            self.ui_manager,
            self.email_manager,
            self.log_manager,
        )

        self.main_window.protocol("WM_DELETE_WINDOW", self.ui_manager.on_closure)
        self.main_window.mainloop()


if __name__ == "__main__":
    PasswordManagerApp()
