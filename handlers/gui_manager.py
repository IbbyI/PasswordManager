import sys
import tkinter as tk
from tkinter import Menu, filedialog, messagebox, Toplevel
from typing import Any

import ttkbootstrap as tb
from ttkbootstrap import ttk

from handlers.account_manager import AccountManager
from handlers.email_manager import EmailManager
from handlers.encryption_manager import EncryptionManager
from handlers.log_manager import LogManager
from handlers.password_generator import PasswordGenerator


class GUIManager:
    def __init__(self, main_window, db_manager) -> None:
        """
        Manages the main gui window for password manager.
        """
        self.style = tb.Style()
        self.style.theme_use("cyborg")

        self.main_window = main_window
        self.db_manager = db_manager
        self.log_manager = LogManager()
        self.encryption_manager = EncryptionManager(self.log_manager)
        self.password_generator = PasswordGenerator(self.main_window)
        self.email_manager = EmailManager(self.log_manager)

        self.initialize_account_manager()

        self.columns = ["ID", "Email", "Username", "Password", "Application"]
        self.build_main_window()

    def initialize_account_manager(self) -> None:
        """
        Initializes the AccountManager class and sets up dependencies
        """
        self.ui_manager = self
        self.account_manager = AccountManager(
            self.main_window,
            self.db_manager,
            self.encryption_manager,
            self.ui_manager,
            self.email_manager,
            self.log_manager,
        )

    def on_closure(self) -> None:
        """
        Confirm Window Closure
        """
        confirm = messagebox.askokcancel(
            "Close Password Manager", "Do you want to close the application?"
        )
        if confirm:
            sys.exit()

    def get_selected(self, action="edit") -> None:
        """
        Retrieves Data From Selected Row.
        """
        selected_data = []
        selected = self.tree.selection()
        if selected:
            item_id = selected[0]
            dict_data = self.tree.item(item_id)
            selected_data = dict_data.get("values", [])
            if not isinstance(selected_data, list):
                selected_data = []

        if action == "edit":
            self.edit_account(selected_data)
        if action == "delete":
            self.account_manager.delete_account(selected_data)

    def build_main_window(self) -> None:
        """
        Creates Main Window
        """
        self.tree = ttk.Treeview(
            self.main_window,
            columns=self.columns,
            show="headings",
            selectmode="browse",
            style="Treeview",
        )
        self.menu = Menu(self.main_window, tearoff=False)
        self.tree.bind("<Button-3>", self.popup_menu)
        self.menu.add_command(
            label="Edit", command=lambda: self.get_selected(action="edit")
        )
        self.menu.add_command(
            label="Delete", command=lambda: self.get_selected(action="delete")
        )

        self.tree.column("ID", width=0, stretch=tk.NO)
        self.tree.heading("ID", text="")

        for col in self.columns[1:]:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor=tk.CENTER)

        self.scrollbar = ttk.Scrollbar(self.main_window, command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        self.scrollbar.pack(side=tk.RIGHT, fill=tk.BOTH)
        self.tree.pack()

        self.button_tree = ttk.Frame(self.main_window)
        self.button_tree.pack(side=tk.BOTTOM, pady=10, anchor=tk.CENTER)
        self.new_pass_button = ttk.Button(
            self.button_tree,
            text="Password Generator",
            command=self.show_generator_window,
        )
        self.add_button = ttk.Button(
            self.button_tree, text="Add Account", command=self.add_account
        )
        self.data_button = ttk.Button(
            self.button_tree, text="Show Data", command=self.show_data
        )
        self.delete_button = ttk.Button(
            self.button_tree,
            text="Delete All Data",
            command=self.account_manager.delete_all,
        )

        self.new_pass_button.pack(side=tk.BOTTOM)
        self.add_button.pack(side=tk.LEFT, pady=5)
        self.data_button.pack(side=tk.LEFT, pady=5)
        self.delete_button.pack(side=tk.LEFT, pady=5)

    def add_account(self) -> None:
        """
        Create New Account Window
        """
        self.new_account_window = Toplevel(self.main_window)
        self.new_account_window.focus()
        self.new_account_window.attributes("-topmost", True)
        self.new_account_window.geometry("280x150")
        self.new_account_window.resizable(False, False)
        self.new_account_window.title("Add Account")

        self.all_entry = []
        for i, label in enumerate(self.columns[1:]):
            ttk.Label(self.new_account_window, text=label).grid(row=i, column=0)
            self.entry = ttk.Entry(self.new_account_window, width=25)
            if i == 2:  # Hide password entry
                self.entry.config(show="*")
            self.entry.grid(row=i, column=1)
            self.all_entry.append(self.entry)

        e1_button = ttk.Button(
            self.new_account_window,
            text="Add Path",
            command=lambda: self.open_file_dialog(self.all_entry[3]),
        )
        e1_button.grid(row=3, column=2, columnspan=1)

        self.opt_in_bool = tk.IntVar()
        opt_in_checkbox = ttk.Checkbutton(
            self.new_account_window,
            text="Opt in for newsletters!",
            variable=self.opt_in_bool,
            onvalue=1,
            offvalue=0,
        )
        opt_in_checkbox.grid(row=4, column=1, columnspan=1)

        submit_button = ttk.Button(
            self.new_account_window,
            text="Submit",
            command=lambda: self.is_entry_empty(self.all_entry),
        )
        submit_button.grid(row=5, column=1, columnspan=1)

    def is_entry_empty(self, entry_list: list[ttk.Entry]) -> bool:
        """
        Highlights empty ttk.Entry widgets using a custom style.
        """
        style = ttk.Style()
        style.configure("Error.TEntry", foreground="red")

        entry_filled = True
        for entry in entry_list:
            if not entry.get().strip():
                entry.configure(style="Error.TEntry")
                entry_filled = False
            else:
                entry.configure(style="TEntry")

        if entry_filled:
            self.account_manager.new_data_handler(
                self.all_entry, self.opt_in_bool, self.new_account_window
            )

        return entry_filled

    def edit_account(self, data: list[Any]) -> None:
        """
        Creates Edit Account Window
        """
        if not data:
            return
        edit_account_window = Toplevel(self.main_window)
        edit_account_window.focus()
        edit_account_window.geometry("300x150")
        edit_account_window.attributes("-topmost", True)
        edit_account_window.resizable(False, False)
        edit_account_window.title("Edit Account")

        edit_entries = []
        for i, label in enumerate(self.columns[1:]):
            ttk.Label(edit_account_window, text=label).grid(row=i, column=0)
            entry = ttk.Entry(edit_account_window, width=30)
            entry.insert(0, data[i + 1])
            entry.grid(row=i, column=1)
            edit_entries.append(entry)

        opt_in_bool = tk.IntVar(value=data[5])
        opt_in_checkbox = ttk.Checkbutton(
            edit_account_window,
            text="Opt in for newsletters!",
            variable=opt_in_bool,
            onvalue=1,
            offvalue=0,
        )
        opt_in_checkbox.grid(row=7, column=1, columnspan=1)

        submit_button = ttk.Button(
            edit_account_window,
            text="Submit",
            command=lambda: self.account_manager.edit_data_handler(
                edit_entries, data, opt_in_bool, edit_account_window
            ),
        )
        submit_button.grid(row=8, column=1, columnspan=1)

        edit_account_window.bind(
            "<Return>",
            lambda event: self.account_manager.edit_data_handler(
                edit_entries, data, opt_in_bool, edit_account_window
            ),
        )

    def popup_menu(self, event: tk.Event) -> None:
        """
        Identify the Account that was Selected
        """
        account_id = self.tree.identify_row(event.y)
        if account_id:
            self.tree.selection_set(account_id)
            try:
                self.menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.menu.grab_release()

    def refresh_tree_view(self) -> None:
        """
        Refresh Treeview
        """
        for data in self.tree.get_children():
            self.tree.delete(data)

    def open_file_dialog(self, entry_widget: ttk.Entry) -> None:
        """
        File dialog for selecting paths
        """
        entry_widget.insert(0, filedialog.askopenfilename())

    def show_data(self) -> None:
        """
        Shows Data in Treeview
        """
        try:
            user_id = self.db_manager.get_user_id()
            if user_id is not None:
                encrypted_data = self.db_manager.fetch_data()
                decrypted_data = [
                    self.encryption_manager.decrypt(data) for data in encrypted_data
                ]
                sliced_data = [data[1:] for data in decrypted_data]
                self.refresh_tree_view()

                for data in sliced_data:
                    self.tree.insert("", tk.END, values=data)
                self.data_button.configure(text="Hide Data", command=self.hide_data)
        except Exception as error:
            messagebox.showerror("Error", str(error))
            self.log_manager.log("Error", f"Could Not Show Data: {error}")
            self.delete_button.configure(state="disabled")
            self.data_button.configure(state="disabled")

    def hide_data(self) -> None:
        """
        Hides Treeview Data
        """
        self.refresh_tree_view()
        self.data_button.configure(text="Show Data", command=self.show_data)
        return

    def show_generator_window(self) -> None:
        """
        Creates Password Generator Window
        """
        self.pwd_gen_window = Toplevel(self.main_window)
        self.pwd_gen_window.focus()
        self.pwd_gen_window.geometry("450x150")
        self.pwd_gen_window.attributes("-topmost", True)
        self.pwd_gen_window.resizable(False, False)
        self.pwd_gen_window.title("Password Generator")

        password_length = tk.IntVar(value=16)

        entry = ttk.Entry(self.pwd_gen_window, width=30)
        slider = tk.Scale(
            self.pwd_gen_window,
            variable=password_length,
            from_=8,
            to=24,
            orient="horizontal",
            sliderlength=15,
            length=100,
        )
        slider_value = ttk.Label(self.pwd_gen_window, textvariable=password_length)
        slider.set(password_length.get())

        option_special = ttk.Checkbutton(
            self.pwd_gen_window,
            text="Include Special Characters?",
            variable=self.password_generator.include_special,
            command=self.password_generator.update_alphabet,
        )
        option_caps = ttk.Checkbutton(
            self.pwd_gen_window,
            text="Include Uppercase Letters?",
            variable=self.password_generator.include_caps,
            command=self.password_generator.update_alphabet,
        )
        option_numbers = ttk.Checkbutton(
            self.pwd_gen_window,
            text="Include Numbers?",
            variable=self.password_generator.include_numbers,
            command=self.password_generator.update_alphabet,
        )

        def on_generate() -> None:
            """
            Updates Generated Password Entry
            """
            password = self.password_generator.generate_password(password_length.get())
            entry.delete(0, tk.END)
            entry.insert(0, password)

        generate_pwd_button = ttk.Button(
            self.pwd_gen_window, text="Generate Password", command=on_generate
        )
        self.pwd_gen_window.bind("<Return>", lambda event: on_generate())

        entry.grid(row=1, column=3, padx=25, pady=15, sticky="s")
        slider.grid(row=2, column=3, sticky="n")
        slider_value.grid(row=3, column=3, sticky="n")
        generate_pwd_button.grid(row=4, column=3, sticky="n")
        option_special.grid(row=2, column=5, columnspan=2, sticky="w")
        option_caps.grid(row=3, column=5, columnspan=2, sticky="w")
        option_numbers.grid(row=4, column=5, columnspan=2, sticky="w")
