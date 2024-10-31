
import tkinter as tk
from threading import Thread
from tkinter import messagebox

class AccountManager:
    def __init__(self, main_window, db_manager, encryption_manager, ui_manager, email_manager):
        self.main_window = main_window
        self.db_manager = db_manager
        self.encryption_manager = encryption_manager
        self.ui_manager = ui_manager
        self.email_manager = email_manager
        self.user_id = self.db_manager.get_user_id()
        self.tuple_email = self.db_manager.get_email(self.user_id)
        self.email = self.tuple_email[0]

        self.columns = ["ID", "Email", "Username", "Password", "Application"]

    # Handles New Account Data
    def new_data_handler(self, all_entry, opt_in_bool, window):
        try:
            new_acc_data = [entry.get() for entry in all_entry]
            new_acc_data.append(opt_in_bool.get())

            if not self.email_manager.is_valid_email(new_acc_data[0]):
                messagebox.showwarning("Invalid Email", "Please enter a valid email address.")
                return

            if self.email_manager.strength(new_acc_data[2]) is True:
                messagebox.showwarning("Weak Password", "Your Password has been leaked.\nConsider changing your password.")
            self.db_manager.insert_account(new_acc_data)
            window.destroy()
            self.ui_manager.show_data()
        except Exception as e:
            raise Exception(f"Error: {e}")


    # Handles Edited Account Data 
    def edit_data_handler(self, all_entry, selected_data, opt_in_bool, window):
        edited_data = [entry.get() for entry in all_entry]

        if edited_data == selected_data[1:5]:
            window.destroy()
            return
        
        if not self.email_manager.is_valid_email(edited_data[0]):
            messagebox.showwarning("Invalid Email", "Please enter a valid email address.")
            return

        try:
            if self.email_manager.strength(edited_data[2]) is True:
                messagebox.showwarning("Weak Password", "Your Password has been leaked.\nConsider changing your password.")
            
            edited_data.append(opt_in_bool.get())
            encrypted_data = self.encryption_manager.encrypt(edited_data)
            self.db_manager.update_account(selected_data[0], encrypted_data)

            window.destroy()
            self.ui_manager.show_data()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to update account: {e}")


    # Delete an Account From Database
    def delete_account(self, selected_data):
        if not selected_data:
            return

        if messagebox.askquestion(title="Delete Account", message="You're about to delete this account.\nDo you wish to proceed?", icon="warning") == "yes":
            try:
                self.db_manager.delete_account(selected_data[0])
                self.ui_manager.show_data()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete account: {e}")
    

    # Delete Database
    def delete_all(self):
        result = self.db_manager.check_db_for_data()

        if result is not None:
            self.delete_warning = messagebox.askquestion(title="Delete All Data", 
            message="You're about to delete all data.\nDo you wish to proceed?", 
            icon="warning")

        else:
            messagebox.showerror("Error", "Error: 003 No Data to Delete.")
            self.ui_manager.refresh_tree_view()

        if self.delete_warning == "yes":
                self.db_manager.delete_all()
                self.ui_manager.refresh_tree_view()
        else:
            pass



