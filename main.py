import tkinter as tk
import ttkbootstrap as tb
from handlers.databaseManager import DatabaseManager
from handlers.encryptionManager import EncryptionManager
from handlers.passwordGenerator import PasswordGenerator
from handlers.emailManager import EmailManager
from handlers.guiManager import GUIManager
from handlers.accountManager import AccountManager
from handlers.masterLogin import MasterLogin


class PasswordManagerApp:
    def __init__(self):
        self.master_login = MasterLogin(self.on_login_success)


    def on_login_success(self):
        # Initialize Main Tkinter Window With Necessary Classes
        self.main_window = tk.Tk()
        self.main_window.title("Password Manager")
        self.main_window.resizable(False, False)
        self.style = tb.Style()
        self.style.theme_use("cyborg")
        
        self.db_manager = DatabaseManager()
        self.encryption_manager = EncryptionManager()
        self.email_manager = EmailManager()
        self.password_generator = PasswordGenerator(self.main_window)
        self.ui_manager = GUIManager(self.main_window)
        self.account_manager = AccountManager(self.main_window, self.db_manager, self.encryption_manager, self.ui_manager, self.email_manager)
        self.main_window.mainloop()


if __name__ == "__main__":
    PasswordManagerApp()