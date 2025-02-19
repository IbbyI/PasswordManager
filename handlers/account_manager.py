import tkinter as tk
from ttkbootstrap import ttk
from sre_constants import ANY
from tkinter import Variable, messagebox
from typing import Any


class AccountManager:
    """
    Manages account operations including creating, editing, deleting, and handling database interactions.
    """

    def __init__(
        self,
        main_window,
        db_manager,
        encryption_manager,
        ui_manager,
        email_manager,
        log_manager,
    ) -> None:
        """
        Initialize the AccountManager with dependencies and user information.
        """
        self.main_window = main_window
        self.db_manager = db_manager
        self.encryption_manager = encryption_manager
        self.ui_manager = ui_manager
        self.email_manager = email_manager
        self.log_manager = log_manager

        self.user_id = self.db_manager.get_user_id()
        self.tuple_email = self.db_manager.get_email(self.user_id)
        self.email = self.tuple_email[0]

        self.columns = ["ID", "Email", "Username", "Password", "Application"]

    def new_data_handler(
        self,
        all_entry: list[ttk.Entry],
        opt_in_bool: tk.IntVar,
        window: tk.Toplevel,
    ) -> None:
        """
        Handle creation of a new account by validating and saving the data.
        """

        try:
            new_acc_data = [entry.get() for entry in all_entry]
            new_acc_data.append(str(opt_in_bool.get()))

            if not self.email_manager.is_valid_email(new_acc_data[0]):
                messagebox.showwarning(
                    "Invalid Email", "Please enter a valid email address."
                )
                return

            if self.email_manager.strength(new_acc_data[2]):
                messagebox.showwarning(
                    "Weak Password",
                    "Your Password has been leaked.\nConsider changing your password.",
                )
            encrypted_data = self.encryption_manager.encrypt(new_acc_data)
            self.db_manager.insert_account(encrypted_data)
            window.destroy()
            self.ui_manager.show_data()

        except Exception as error:
            self.log_manager.log("error", f"Could Not Create Account: {error}")
            raise Exception(f"Could Not Create Account: {error}")

    def edit_data_handler(
        self,
        all_entry: list[ttk.Entry],
        selected_data: list[Any],
        opt_in_bool: tk.IntVar,
        window: tk.Toplevel,
    ) -> None:
        """
        Handle editing of an existing account by validating and updating the data.
        """
        edited_data = [entry.get() for entry in all_entry]

        if edited_data == selected_data[1:5]:
            window.destroy()
            return

        if not self.email_manager.is_valid_email(edited_data[0]):
            messagebox.showwarning(
                "Invalid Email", "Please enter a valid email address."
            )
            return

        try:
            if self.email_manager.strength(edited_data[2]):
                messagebox.showwarning(
                    "Weak Password",
                    "Your Password has been leaked.\nConsider changing your password.",
                )

            edited_data.append(str(opt_in_bool.get()))
            encrypted_data = self.encryption_manager.encrypt(edited_data)
            self.db_manager.update_account(selected_data[0], encrypted_data)

            window.destroy()
            self.ui_manager.show_data()

        except Exception as error:
            messagebox.showerror("Error", f"Failed to update account: {error}")
            self.log_manager.log("Error", f"Failed to update account: {error}")

    def delete_account(self, selected_data: list[Any]) -> None:
        """
        Delete a specific account from the database after user confirmation.
        """
        if not selected_data:
            return

        confirm = messagebox.askquestion(
            title="Delete Account",
            message="You're about to delete this account.\nDo you wish to proceed?",
            icon="warning",
        )

        if confirm == "yes":
            try:
                rows_affected = self.db_manager.delete_account(selected_data[0])
                self.ui_manager.show_data()
                self.delete_data_email(rows_affected)
            except Exception as error:
                messagebox.showerror("Error", f"Failed to delete account: {error}")
                self.log_manager.log("Error", f"Failed to delete account: {error}")

    def delete_all(self) -> None:
        """
        Delete all account data from the database after user confirmation.
        """
        if not self.db_manager.check_db_for_data():
            messagebox.showerror("Error", "Error: 003 No Data to Delete.")
            self.ui_manager.refresh_tree_view()
            return

        confirm = messagebox.askquestion(
            title="Delete All Data",
            message="You're about to delete all accounts.\nDo you wish to proceed?",
            icon="warning",
        )

        if confirm == "yes":
            try:
                rows_affected = self.db_manager.delete_all_accounts()
                self.ui_manager.refresh_tree_view()
                self.delete_data_email(rows_affected)
            except Exception as error:
                messagebox.showerror("Error", f"Failed to delete all data: {error}")
                self.log_manager.log("Error", f"Failed to delete all data: {error}")

    def delete_data_email(self, rows: int) -> None:
        """
        Sends an email notification after deleting account data.
        """
        email = self.db_manager.get_email(self.user_id)[0]
        self.email_manager.send_email(
            email, file_path="./templates/delete_account.html", number_of_accounts=rows
        )
