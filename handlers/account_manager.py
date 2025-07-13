import customtkinter as ctk
from tkinter import messagebox


class AccountManager:
    """
    Manages account operations including creating, editing, deleting, and handling database interactions.
    """

    def __init__(
        self,
        main_window,
        database_manager,
        encryption_manager,
        gui_manager,
        email_manager,
        log_manager,
        password_strength,
    ) -> None:
        """
        Initialize the AccountManager with dependencies and user information.

        Args:
            main_window: The main window of the application.
            database_manager: The database manager object.
            encryption_manager: The encryption manager object.
            gui_manager: The UI manager object.
            email_manager: The email manager object.
            log_manager: The log manager object.
        """
        self.main_window = main_window
        self.database_manager = database_manager
        self.encryption_manager = encryption_manager
        self.gui_manager = gui_manager
        self.email_manager = email_manager
        self.log_manager = log_manager
        self.passsword_strength = password_strength

        self.user_id: int | None = self.database_manager.get_user_id()
        self.tuple_email: str | None = self.database_manager.get_email(self.user_id)
        if self.tuple_email:
            self.email: str = self.tuple_email[0]

        self.columns = ["ID", "Email", "Username", "Password", "Application"]

    def new_data_handler(
        self,
        all_entry: list[ctk.CTkEntry],
        opt_in_bool: ctk.IntVar,
        window: ctk.CTkToplevel,
    ) -> None:
        """
        Handle creation of a new account by validating and saving the data.
        Args:
            all_entry (list[tctk.CTkEntry]): A list of all entry widgets in the window.
            opt_in_bool (tk.IntVar): A boolean variable to check if the user has opted in for newsletters.
            window (tk.Toplevel): The new account window object to be destroyed after saving the data.
        """
        try:
            new_acc_data = [entry.get() for entry in all_entry]
            new_acc_data.append(str(opt_in_bool.get()))

            if not self.email_manager.is_valid_email(new_acc_data[0]):
                messagebox.showwarning(
                    "Invalid Email", "Please enter a valid email address."
                )
                return

            if self.passsword_strength.check_pwned(new_acc_data[2]):
                messagebox.showwarning(
                    "Weak Password",
                    "Your Password has been leaked.\nConsider changing your password.",
                )
            encrypted_data = self.encryption_manager.encrypt(new_acc_data)
            self.database_manager.insert_account(encrypted_data)
            window.destroy()
            self.gui_manager.show_data()

        except Exception as error:
            self.log_manager.log("error", f"Could Not Create Account: {error}")
            raise Exception(f"Could Not Create Account: {error}")

    def edit_data_handler(
        self,
        all_entry: list[ctk.CTkEntry],
        selected_data: list[int | str],
        opt_in_bool: ctk.IntVar,
        window: ctk.CTkToplevel,
    ) -> None:
        """
        Handle editing of an existing account by validating and updating the data.
        Args:
            all_entry (list[ctk.CTkEntry]): A list of all entry widgets in the window.
            selected_data (list[int | str]]): The data of the selected account to be edited.
            opt_in_bool (Ctk.IntVar): A boolean variable to check if the user has opted in for newsletters.
            window (ctk.CTkToplevel): The edit account window object to be destroyed after saving the data.
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
            if self.passsword_strength.check_pwned(edited_data[2]):
                messagebox.showwarning(
                    "Weak Password",
                    "Your Password has been leaked.\nConsider changing your password.",
                )

            edited_data.append(str(opt_in_bool.get()))
            encrypted_data = self.encryption_manager.encrypt(edited_data)
            self.database_manager.update_account(int(selected_data[0]), encrypted_data)

            window.destroy()
            self.gui_manager.show_data()

        except Exception as error:
            messagebox.showerror("Error", f"Failed to update account: {error}")
            self.log_manager.log("Error", f"Failed to update account: {error}")

    def delete_account(self, selected_data: list[int | str]) -> None:
        """
        Delete a specific account from the database after user confirmation.
        Args:
            selected_data (list[int | str]): The data of the selected account to be deleted.
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
                rows_affected = self.database_manager.delete_account(selected_data[0])
                self.gui_manager.show_data()
                if rows_affected:
                    self.delete_data_email(rows_affected)
            except Exception as error:
                messagebox.showerror("Error", f"Failed to delete account: {error}")
                self.log_manager.log("Error", f"Failed to delete account: {error}")

    def delete_all(self) -> None:
        """
        Delete all account data from the database after user confirmation.
        """
        if not self.database_manager.check_db_for_data():
            messagebox.showerror("Error", "Error: 003 No Data to Delete.")
            self.gui_manager.refresh_tree_view()
            return

        confirm = messagebox.askquestion(
            title="Delete All Data",
            message="You're about to delete all accounts.\nDo you wish to proceed?",
            icon="warning",
        )

        if confirm == "yes":
            try:
                rows_affected = self.database_manager.delete_all_accounts()
                self.gui_manager._clear_cache()
                self.gui_manager.refresh_tree_view()
                if rows_affected:
                    self.delete_data_email(rows_affected)
            except Exception as error:
                messagebox.showerror("Error", f"Failed to delete all data: {error}")
                self.log_manager.log("Error", f"Failed to delete all data: {error}")

    def delete_data_email(self, rows: int) -> None:
        """
        Sends an email notification after deleting account data.
        Args:
            rows (int): The number of rows deleted in the database.
        """
        email_tuple = self.database_manager.get_email(self.user_id)
        if email_tuple:
            email = email_tuple[0]
            self.email_manager.send_email(
                email,
                file_path="./templates/delete_account.html",
                number_of_accounts=rows,
            )
        else:
            self.log_manager.log("Error", f"Could not send email for {self.user_id}")
