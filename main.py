import tkinter as tk
import ttkbootstrap as tb
from databaseManager import DatabaseManager
from encryptionManager import EncryptionManager
from passwordGenerator import PasswordGenerator
from emailManager import EmailManager
from guiManager import GUIManager
from accountManager import AccountManager


class PasswordManagerApp:
    def __init__(self):
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