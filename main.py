import os
import string
import secrets
import sqlite3
import pyperclip
import create_key
import send_email
import email_check
import strength_test
import tkinter as tk
import ttkbootstrap as tb
from cryptography.fernet import Fernet
from tkinter import ttk, filedialog, messagebox, Menu, Scale


class PasswordManager:
    # Main GUI Window
    def __init__(self):
        self.main_window = tk.Tk()
        self.main_window.title("Password Manager")
        self.main_window.resizable(False, False)
        self.main_window.option_add("*tearOff", False)
        self.style = tb.Style()
        self.style.theme_use("cyborg")
        self.columns = ["ID", "Email", "Username", "Password", "Application"]
        self.ui()


    # GUI Layout
    def ui(self):
        self.menu = Menu(self.main_window, tearoff=False)
        self.menu.add_command(label="Edit", command=lambda : self.get_selected(action="edit"))
        self.menu.add_command(label="Delete", command=lambda : self.get_selected(action="delete"))

        self.tree = ttk.Treeview(self.main_window, columns=self.columns, show="headings", selectmode="browse")
        self.tree.bind('<Button-3>', self.popup_menu)
        self.tree.column("ID", width=0, stretch=tk.NO)
        self.tree.heading("ID", text="")
        
        for col in self.columns[1:]:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor=tk.CENTER)

        self.scrollbar = ttk.Scrollbar(self.main_window, command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        self.scrollbar.pack(side=tk.RIGHT, fill=tk.BOTH)
        self.tree.pack()

        self.button_tree = tk.Frame(self.main_window)
        self.button_tree.pack(side=tk.BOTTOM, pady=10, anchor=tk.CENTER)

        self.new_pass_button = tk.Button(self.button_tree, text="Password Generator", command=self.password_generator)
        self.add_button = tk.Button(self.button_tree, text="Add Account", command=self.add_data)
        self.data_button = tk.Button(self.button_tree, text="Show Data", command=self.show_data)
        self.delete_button = tk.Button(self.button_tree, text="Delete All Data", command=self.delete_all)

        self.new_pass_button.pack(side=tk.BOTTOM)
        self.add_button.pack(side=tk.LEFT, pady=5)
        self.data_button.pack(side=tk.LEFT, pady=5)
        self.delete_button.pack(side=tk.LEFT, pady=5)
        return


    #Creates Popup Menu On Account
    def popup_menu(self, event):
        account_id = self.tree.identify_row(event.y)
        if account_id:
            self.tree.selection_set(account_id)
            try:
                self.menu.tk_popup(event.x_root, event.y_root)    
            finally:
                self.menu.grab_release()


    #Gets Data on Clicked Accounts
    def get_selected(self, action="edit"):
        selected = self.tree.selection()
        if selected:
            dict_data = self.tree.item(selected)
            self.selected_data = dict_data["values"]

        if action == "edit":
            self.edit_account(self.selected_data)
        if action == "delete":
            self.delete_account(self.selected_data)
        return


    #Deletes Selected Account
    def delete_account(self, data=None):
        if not data:
            self.get_selected(action="delete")
        else:
            confirmation = messagebox.askquestion(title="Delete Account", 
            message="You're about to delete this account.\nDo you wish to proceed?", 
            icon="warning")

            if confirmation == "yes":
                with self.connect_db() as conn:
                    try:
                        cursor = conn.cursor()
                        cursor.execute("DELETE FROM accounts WHERE id = ?", (data[0],))
                        conn.commit()
                        self.show_data()
                    except Exception as error:
                        print(error)
        return


    # Connect to Database
    def connect_db(self):
        return sqlite3.connect("database.db")


    # Read Fernet Key
    def read_key(self):
        key = os.getenv("FERNET_KEY")
        if not key:
            messagebox.showwarning("Error 002: Encryption key is missing or invalid.")
            return None
        return key


    # Get Data From Local Database
    def fetch_data(self):
        with self.connect_db() as conn:
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM accounts")
                data = cursor.fetchall()
            except Exception as error:
                messagebox.showerror("Error", "Error: 001 Database Does Not Exist.")
                print(error)
                self.data_button.configure(state="disabled")
                self.delete_button.configure(state="disabled")
                return
        return data
    

    # Encrypts New Account Data
    def encrypt(self, data):
        key = self.read_key()   
        cipher = Fernet(key)

        encrypted_email = cipher.encrypt(data[0].encode())  
        encrypted_user = cipher.encrypt(data[1].encode())
        encrypted_pass = cipher.encrypt(data[2].encode())

        encrypted_data = [encrypted_email, encrypted_user, encrypted_pass, data[3], data[4]]
        return encrypted_data
 
 
    # Decrypt Data in Database
    def decrypt_db_data(self):
        data = self.fetch_data()
        key = self.read_key()
        f = Fernet(key)
        decrypted_data = []

        for x in data:
            decrypted_row = list(x)
            for j in range(1, 4):
                decrypted_row[j] = f.decrypt(x[j]).decode()
            
            decrypted_data.append(tuple(decrypted_row))
        return decrypted_data   


    # Insert New Account Into Database
    def insert_account(self, data):
        encryted_data = self.encrypt(data)
        with self.connect_db() as conn:
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS accounts (
                        id INTEGER PRIMARY KEY, 
                        email TEXT,
                        username TEXT, 
                        password TEXT,
                        application TEXT, 
                        opt_in INTEGER 
                    )
                """)
                cursor.execute("""
                    INSERT INTO accounts(
                        id, 
                        email, 
                        username, 
                        password, 
                        application, 
                        opt_in
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (None, encryted_data[0], encryted_data[1], encryted_data[2], encryted_data[3], encryted_data[4]))
                conn.commit()
            except Exception as error:
                messagebox.showerror("Error", "Error 004: Account Could Not Be Added to Database")
                print(error)
                self.new_account_window.destroy()
                self.delete_button.pack(side=tk.LEFT, pady=10)
        self.data_button.configure(text="Show Data", command=self.show_data)
        return


    # Windows Explorer Dialog
    def open_file_dialog(self, entry_widget):
        entry_widget.insert(0, filedialog.askopenfilename())
        return


    # Add Account Window
    def add_data(self):
        self.new_account_window = tk.Toplevel(self.main_window)
        self.new_account_window.attributes('-topmost', True)
        self.new_account_window.geometry("280x150")
        self.new_account_window.resizable(False, False)
        self.new_account_window.title("Add Account")
        style = tb.Style()
        style.theme_use('cyborg')

        self.entries = []

        for i, label in enumerate(self.columns[1:]):
            tk.Label(self.new_account_window, text=label).grid(row=i, column=0)
            entry = tk.Entry(self.new_account_window, width=25)
            if i == 2:
                entry.config(show='*')
            entry.grid(row=i, column=1)
            self.entries.append(entry)
        
        self.e1_button = tk.Button(self.new_account_window, text="Add Path", command=lambda: self.open_file_dialog(self.entries[3]))
        self.e1_button.grid(row=3, column=2, columnspan=1)

        self.opt_in_bool = tk.IntVar()
        self.opt_in_checkbox = tk.Checkbutton(self.new_account_window, text="Opt in for newsletters!", variable=self.opt_in_bool ,onvalue=1, offvalue=0, command=lambda: self.checkbox_checker)
        self.opt_in_checkbox.grid(row=4, column=1, columnspan=1)

        self.submit_button = tk.Button(self.new_account_window, text="Submit", command=lambda: self.new_data_handler(self.entries))
        self.submit_button.grid(row=5, column=1, columnspan=1)
        return


    # Creates Window to Edit Accounts
    def edit_account(self, event=None):        
        self.edit_account_window = tk.Toplevel(self.main_window)
        self.edit_account_window.geometry("300x150")
        self.edit_account_window.attributes('-topmost', True)
        self.edit_account_window.resizable(False, False)
        self.edit_account_window.title("Edit Account")
        style = tb.Style()
        style.theme_use("cyborg")

        self.edit_entries = []

        for i, label in enumerate(self.columns[1:]):
            tk.Label(self.edit_account_window, text=label).grid(row=i, column=0)
            entry = tk.Entry(self.edit_account_window, width=30)
            entry.insert(0, self.selected_data[i + 1])
            entry.grid(row=i, column=1)
            self.edit_entries.append(entry)

        entry.focus_set()
        self.opt_in_bool = tk.IntVar()
        self.opt_in_checkbox = tk.Checkbutton(self.edit_account_window, text="Opt in for newsletters!", variable=self.opt_in_bool ,onvalue=1, offvalue=0, command=lambda: self.checkbox_checker)
        
        if self.selected_data[5] != 0:
            self.opt_in_checkbox.select()

        self.opt_in_checkbox.grid(row=7, column=1, columnspan=1)
        self.submit_button = tk.Button(self.edit_account_window, text="Submit", command=lambda: self.edit_data_handler())
        self.submit_button.grid(row=8, column=1, columnspan=1)
        return
    

    # Submits New Account Data for Encryption
    def new_data_handler(self, entries):
        self.new_acc_data = []
        for i in entries:
            self.new_acc_data.append(i.get())
        self.new_acc_data.append(self.opt_in_bool.get())

        try:
            while email_check.email_check(self.new_acc_data[0]) is False:
                return
            
            self.data_button.pack(side=tk.LEFT, pady=10)
            self.delete_button.pack(side=tk.LEFT, pady=10)

            strength_test.strength(self.new_acc_data[2])

            self.insert_account(self.new_acc_data)
            self.new_account_window.destroy()
            self.show_data()


            with open("welcome.html") as file:
                send_email.send_email(self.new_acc_data[0], file.read())

            self.data_button.configure(state="normal")
            self.delete_button.configure(state="normal")
        except send_email.smtplib.SMTPResponseException:
            print("Invalid SMTP Credentials. Could not send email.")
        return


    # Handles the Edited Account Data
    def edit_data_handler(self):
        raw_edited_data = [entry.get() for entry in self.edit_entries]

        if raw_edited_data == self.selected_data[1:5]:
            self.edit_account_window.destroy()
            return
        
        while email_check.email_check(raw_edited_data[0]) is False:
            return
        
        strength_test.strength(raw_edited_data[2])
        raw_edited_data.append(self.opt_in_bool.get())
        self.edited_data = self.encrypt(raw_edited_data)
        
        with self.connect_db() as conn:
            try:
                cursor = conn.cursor()
                set_clause = ", ".join([f"{i} = ?" for i in self.columns[1:]]) + ", opt_in = ?"
                query = f"UPDATE accounts SET {set_clause} WHERE ID = ?"
                params = self.edited_data + [self.selected_data[0]]
                cursor.execute(query, params)
                conn.commit()
                self.edit_account_window.destroy()
                self.show_data()
                with open("edit_data.html") as file:
                    send_email.send_email(raw_edited_data[0], file.read())
            except send_email.smtplib.SMTPResponseException:
                print("Invalid SMTP Credentials. Could not send email.")
            except Exception as error:
                messagebox.showerror("Error", "Error 008: Could Not Update Account")
                print(error)
        return


    # Checkbox Checker
    def checkbox_checker(self):
        if self.entries[4] is True:
            print("Opted in.")
        else:
            print("Not Opted.")
        return


    # Reveals Data
    def show_data(self):
        try:
            data = self.decrypt_db_data()
            if not data:
                messagebox.showerror("Error", "Error: 007 No Data to Show.")
                self.delete_button.configure(state="disabled")
                self.data_button.configure(state="disabled")
            self.refresh()
            for i in data:
                self.tree.insert("", tk.END, values=i)
            self.data_button.configure(text="Hide Data", command=self.hide_data)
        except Exception as error:
            print(error)
            return


    # Hides Revealed Data
    def hide_data(self):
        self.refresh()
        self.data_button.configure(text="Show Data", command=self.show_data)
        return


    # Refresh Treeview
    def refresh(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        return


    # Delete Database
    def delete_all(self):
        with self.connect_db() as conn:
            cursor = conn.cursor()
            cursor.execute('PRAGMA table_info(accounts)')
            result = cursor.fetchone()

        if result is not None:
            self.delete_warning = messagebox.askquestion(title="Delete All Data", 
            message="You're about to delete all data.\nDo you wish to proceed?", 
            icon="warning")

        else:
            messagebox.showerror("Error", "Error: 003 No Data to Delete.")
            self.refresh()
            self.delete_button.configure(state="disabled")
            self.data_button.configure(state="disabled")

        if self.delete_warning == "yes":
            try:
                with self.connect_db() as conn:
                    cursor = conn.cursor()
                cursor.execute("""DROP TABLE accounts""")
                conn.commit()
                self.delete_button.configure()
                self.refresh()
            except send_email.smtplib.SMTPResponseException:
                print("Invalid SMTP Credentials. Could not send email.")
        else:
            pass
        return


    #Password Generator
    def password_generator(self):
        self.pwd_gen_window = tk.Toplevel(self.main_window)
        self.pwd_gen_window.geometry("450x150")
        self.pwd_gen_window.attributes('-topmost', True)
        self.pwd_gen_window.resizable(False, False)
        self.pwd_gen_window.title("Password Generator")
        style = tb.Style()
        style.theme_use("cyborg")
        password_length = tk.IntVar()

        self.entry = tk.Entry(self.pwd_gen_window, width=30)
        slider = tk.Scale(self.pwd_gen_window, variable=password_length, from_=8, to=24, orient="horizontal", sliderlength=15, length=100)
        slider_value = tk.Label(self.pwd_gen_window, textvariable=password_length)

        self.include_special = tk.BooleanVar()
        self.include_caps = tk.BooleanVar()
        self.include_numbers = tk.BooleanVar()

        self.alphabet = list(string.ascii_lowercase)

        option_special = tk.Checkbutton(self.pwd_gen_window, text="Include Special Characters?", variable=self.include_special, command=self.update_alphabet)
        option_caps = tk.Checkbutton(self.pwd_gen_window, text="Include Uppercase Letters? ", variable=self.include_caps,command=self.update_alphabet)
        option_numbers = tk.Checkbutton(self.pwd_gen_window, text="Include Numbers?", variable=self.include_numbers, command=self.update_alphabet)
        generate_pwd_button = tk.Button(self.pwd_gen_window, text="Generate Password", command=lambda : self.generate_password(password_length.get()))
        
        self.entry.grid(row=1, column=3, padx=25, sticky="s")
        slider.grid(row=2, column=3, sticky="s")
        slider_value.grid(row=3, column=3, sticky="s")
        generate_pwd_button.grid(row=4, column=3, sticky="s")
        option_special.grid(row=2, column=5, columnspan=2, sticky="w") 
        option_caps.grid(row=3, column=5, columnspan=2, sticky="w")
        option_numbers.grid(row=4, column=5, columnspan=2, sticky="w")
        return
    

    def update_alphabet(self):
        if self.include_caps.get():
            self.alphabet += list(string.ascii_uppercase)
        if self.include_special.get():
            self.alphabet += list(string.punctuation)
        if self.include_numbers.get():
            self.alphabet += list(string.digits)
        return self.alphabet


    def generate_password(self, length):
        password = ''.join(secrets.choice(self.alphabet) for i in range(length))
        self.entry.delete(0, tk.END)
        self.entry.insert(0, password)
        pyperclip.copy(password)
        return password
    

    # Runs Program
    def run(self):
        self.main_window.mainloop()
    

if __name__ == "__main__":
    app = PasswordManager()
    app.run()
