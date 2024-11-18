import tkinter as tk
from tkinter import messagebox


class AccountManager:
    """
    Manages account operations including creating, editing, deleting, and handling database interactions.
    """

    def __init__(
        self,
        main_window: tk.Tk,
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
        all_entry: list[tk.Entry],
        opt_in_bool: tk.BooleanVar,
        window: tk.Toplevel,
    ) -> None:
        """
        Handle creation of a new account by validating and saving the data.
        """

        try:
            new_acc_data = [entry.get() for entry in all_entry]
            new_acc_data.append(opt_in_bool.get())

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

            self.db_manager.insert_account(new_acc_data)
            window.destroy()
            self.ui_manager.show_data()

        except Exception as e:
            self.log_manager.write_log(error_message=e)
            raise Exception(f"Error: {e}")

    def edit_data_handler(
        self,
        all_entry: list[tk.Entry],
        selected_data: list,
        opt_in_bool: tk.BooleanVar,
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

            edited_data.append(opt_in_bool.get())
            encrypted_data = self.encryption_manager.encrypt(edited_data)
            self.db_manager.update_account(selected_data[0], encrypted_data)

            window.destroy()
            self.ui_manager.show_data()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to update account: {e}")
            self.log_manager.write_log(error_message=e)

    def delete_account(self, selected_data: list) -> None:
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
                self.db_manager.delete_account(selected_data[0])
                self.ui_manager.show_data()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete account: {e}")
                self.log_manager.write_log(error_message=e)

    def delete_all(self) -> None:
        """
        Delete all account data from the database after user confirmation.
        """
        if self.db_manager.check_db_for_data() is None:
            messagebox.showerror("Error", "Error: 003 No Data to Delete.")
            self.ui_manager.refresh_tree_view()
            return

        confirm = messagebox.askquestion(
            title="Delete All Data",
            message="You're about to delete all data.\nDo you wish to proceed?",
            icon="warning",
        )

        if confirm == "yes":
            try:
                self.db_manager.delete_all()
                self.ui_manager.refresh_tree_view()
            except Exception as e:
                messagebox.showerror(
                    "Error", f"Failed to delete all data: {e}")
                self.log_manager.write_log(error_message=e)
