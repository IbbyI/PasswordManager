import sys
from typing import Any
import customtkinter as ctk
from tkinter import Menu, filedialog, messagebox, Event
from ttkbootstrap import Treeview, Style

from handlers.account_manager import AccountManager
from handlers.email_manager import EmailManager
from handlers.encryption_manager import EncryptionManager
from handlers.log_manager import LogManager
from handlers.password_generator import PasswordGenerator
from handlers.password_strength import PasswordStrength


class GUIManager:
    """
    Manages the main gui window for password manager.
    """

    def __init__(self, main_window, database_manager) -> None:
        """
        Initialize the GUIManager with the main window and database manager object.
        Args:
            main_window: The main window of the application.
            database_manager: The database manager object.
        """
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.main_window = main_window
        self.database_manager = database_manager
        self.password_strength = PasswordStrength()
        self.log_manager = LogManager()
        self.password_generator = PasswordGenerator()
        self.email_manager = EmailManager(self.log_manager)
        self.encryption_manager = EncryptionManager(self.log_manager)
        self.initialize_account_manager()

        self.placeholder_text = [
            "Enter Email",
            "Enter Username",
            "Enter password",
            "Website/Application",
        ]
        self._data_cache = None
        self.columns = ["ID", "Email", "Username", "Password", "Application"]
        self.build_main_window()

    def _clear_cache(self) -> None:
        """
        Clears the data cache.
        """
        self._data_cache = None
        self.log_manager.log("info", "Cache cleared successfully.")

    def initialize_account_manager(self) -> None:
        """
        Initializes the AccountManager class and sets up dependencies
        """
        self.gui_manager = self
        self.account_manager = AccountManager(
            self.main_window,
            self.database_manager,
            self.encryption_manager,
            self.gui_manager,
            self.email_manager,
            self.log_manager,
            self.password_strength,
        )

    def on_closure(self, event=None) -> None:
        """
        Confirm Window Closure
        """
        confirm = messagebox.askokcancel(
            "Close Password Manager", "Do you want to close the application?"
        )
        if confirm:
            sys.exit()

    def get_selected(self, action) -> None:
        """
        Retrieves Data From Selected Row.
        Args:
            action (str): Action to Perform. Defaults to None.
        """
        selected_data = []
        selected = self.treeview.selection()
        if selected:
            item_id = selected[0]
            dict_data = self.treeview.item(item_id)
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
        style = Style()
        style.theme_use("darkly")
        bg_color = self.main_window._apply_appearance_mode(
            ctk.ThemeManager.theme["CTkFrame"]["fg_color"]
        )
        text_color = self.main_window._apply_appearance_mode(
            ctk.ThemeManager.theme["CTkLabel"]["text_color"]
        )
        selected_color = self.main_window._apply_appearance_mode(
            ctk.ThemeManager.theme["CTkButton"]["fg_color"]
        )
        style.configure("TMenubutton", background=bg_color, foreground=text_color)

        self.treeview = Treeview(
            self.main_window,
            columns=self.columns,
            show="headings",
            selectmode="browse",
        )
        self.menu = Menu(self.main_window, tearoff=False)

        self.treeview.bind("<Button-3>", self.popup_menu)
        self.menu.add_command(
            label="Edit", command=lambda: self.get_selected(action="edit")
        )
        self.menu.add_command(
            label="Delete", command=lambda: self.get_selected(action="delete")
        )

        self.treeview.column("ID", width=0, stretch=ctk.NO)
        self.treeview.heading("ID", text="")

        for col in self.columns[1:]:
            self.treeview.heading(col, text=col)
            self.treeview.column(col, anchor=ctk.CENTER)

        self.scrollbar = ctk.CTkScrollbar(self.treeview, command=self.treeview.yview)
        self.treeview.configure(yscrollcommand=self.scrollbar.set)

        self.scrollbar.pack(side=ctk.RIGHT, fill=ctk.Y)
        self.treeview.pack(side=ctk.TOP, fill=ctk.BOTH, expand=True)

        style.map(
            "Treeview",
            background=[("selected", bg_color)],
            foreground=[("selected", selected_color)],
        )

        self.button_tree = ctk.CTkFrame(
            self.main_window,
            fg_color="#1a1b1b",
        )
        self.button_tree.pack(side=ctk.BOTTOM, pady=10, anchor=ctk.CENTER)
        self.new_pass_button = ctk.CTkButton(
            self.button_tree,
            text="Password Generator",
            width=220,
            height=50,
            font=("Arial", 28),
            command=self.password_generator.generate_window,
        )
        self.add_button = ctk.CTkButton(
            self.button_tree,
            text="Add Account",
            width=220,
            height=50,
            font=("Arial", 28),
            command=self.add_account,
        )
        self.data_button = ctk.CTkButton(
            self.button_tree,
            text="Show Data",
            width=220,
            height=50,
            font=("Arial", 28),
            command=self.show_data,
        )
        self.delete_button = ctk.CTkButton(
            self.button_tree,
            text="Delete All Data",
            width=220,
            height=50,
            font=("Arial", 28),
            command=self.account_manager.delete_all,
        )
        self.new_pass_button.pack(side=ctk.BOTTOM)
        self.add_button.pack(side=ctk.LEFT, padx=3, pady=3)
        self.data_button.pack(side=ctk.LEFT, padx=3, pady=3)
        self.delete_button.pack(side=ctk.LEFT, padx=3, pady=3)

    def add_account(self) -> None:
        """
        Create New Account Window
        """
        self.new_account_window = ctk.CTkToplevel(self.main_window)
        self.new_account_window.focus()
        self.new_account_window.attributes("-topmost", True)
        self.new_account_window.geometry("600x350+550+150")
        self.new_account_window.resizable(False, False)
        self.new_account_window.title("Add Account")

        new_entries = []
        for i, label in enumerate(self.columns[1:]):
            ctk.CTkLabel(
                self.new_account_window,
                width=240,
                height=48,
                font=("Arial", 25),
                text=label,
            ).grid(row=i, column=0, pady=2)

            self.entry = ctk.CTkEntry(
                self.new_account_window,
                placeholder_text=self.placeholder_text[i],
                width=240,
                height=48,
                font=("Arial", 25),
                border_width=2,
            )
            if i == 2:
                self.entry.configure(show="*")
            self.entry.grid(row=i, column=1, pady=2)

            new_entries.append(self.entry)

        e1_button = ctk.CTkButton(
            self.new_account_window,
            text="📁",
            width=50,
            height=48,
            font=("Arial", 25),
            command=lambda: self.open_file_dialog(new_entries[3]),
        )
        e1_button.grid(row=3, column=2, columnspan=1, padx=0)

        self.opt_in_bool = ctk.IntVar()
        opt_in_checkbox = ctk.CTkCheckBox(
            self.new_account_window,
            text="Opt in for newsletters!",
            width=225,
            height=43,
            font=("Arial", 25),
            variable=self.opt_in_bool,
            onvalue=1,
            offvalue=0,
        )
        opt_in_checkbox.grid(row=4, column=1, pady=2)

        submit_button = ctk.CTkButton(
            self.new_account_window,
            text="Submit",
            width=225,
            height=43,
            font=("Arial", 25),
            command=lambda: self.is_entry_empty(new_entries)
            and self.account_manager.new_data_handler(
                new_entries, self.opt_in_bool, self.new_account_window
            ),
        )
        self.new_account_window.bind(
            "<Return>",
            lambda event: self.is_entry_empty(new_entries)
            and self._handle_new_account(
                new_entries, self.opt_in_bool, self.new_account_window
            ),
        )
        submit_button.grid(row=5, column=1, columnspan=1, pady=2)

    def _handle_new_account(self, entries, opt_in_bool, window) -> None:
        """
        Handles new account submission and clears cache.
        Args:
            entries (list[ctk.CTkEntry]): List of entry widgets.
            opt_in_bool (ctk.IntVar): Checkbox state for opt-in.
            window (ctk.CTkToplevel): The window to close after submission.
        """
        self.account_manager.new_data_handler(entries, opt_in_bool, window)
        self._clear_cache()

    def is_entry_empty(self, entry_list: list[ctk.CTkEntry]) -> bool:
        """
        Highlights empty ctk.Entry widgets using a custom style.
        Args:
            entry_list (list[ctk.CTkEntry]): A list of ctk.Entry widgets.
        Returns:
            bool: True if all ctk.Entry widgets are filled, False otherwise.
        """
        entry_filled = True
        for entry in entry_list:
            if not entry.get().strip():
                entry.configure(border_width=1, border_color="red")
                entry_filled = False
            else:
                entry.configure(border_width=0)

        if entry_filled:
            return True
        return False

    def edit_account(self, data: list[Any]) -> None:
        """
        Creates Edit Account Window
        Args:
            data (list[Any]): Data to be edited.
        """
        if not data:
            return
        edit_account_window = ctk.CTkToplevel(self.main_window)
        edit_account_window.focus()
        edit_account_window.geometry("600x350+550+150")
        edit_account_window.attributes("-topmost", True)
        edit_account_window.resizable(False, False)
        edit_account_window.title("Edit Account")

        edit_entries = []
        for i, label in enumerate(self.columns[1:]):
            ctk.CTkLabel(
                edit_account_window,
                text=label,
                width=240,
                height=48,
                font=("Arial", 25),
            ).grid(row=i, column=0)

            entry = ctk.CTkEntry(
                edit_account_window, width=240, height=48, font=("Arial", 25)
            )
            entry.insert(0, data[i + 1])
            entry.grid(row=i, column=1)
            edit_entries.append(entry)

        opt_in_bool = ctk.IntVar(value=data[5])
        opt_in_checkbox = ctk.CTkCheckBox(
            edit_account_window,
            text="Opt in for newsletters!",
            width=225,
            height=43,
            font=("Arial", 25),
            variable=opt_in_bool,
            onvalue=1,
            offvalue=0,
        )
        opt_in_checkbox.grid(row=7, column=1, columnspan=1)

        submit_button = ctk.CTkButton(
            edit_account_window,
            text="Submit",
            width=225,
            height=43,
            font=("Arial", 25),
            command=lambda: self.is_entry_empty(edit_entries)
            and self.account_manager.edit_data_handler(
                edit_entries, data, opt_in_bool, edit_account_window
            ),
        )
        submit_button.grid(row=8, column=1, columnspan=1)

        edit_account_window.bind(
            "<Return>",
            lambda event: self.is_entry_empty(edit_entries)
            and self._handle_edit_account(
                edit_entries, data, opt_in_bool, edit_account_window
            ),
        )

    def _handle_edit_account(self, entries, data, opt_in_bool, window) -> None:
        """
        Handles edited account submission and clears cache.
        Args:
            entries (list[ctk.CTkEntry]): List of entry widgets.
            data (list[Any]): Original data to be edited.
            opt_in_bool (ctk.IntVar): Checkbox state for opt-in.
            window (ctk.CTkToplevel): The window to close after submission.
        """
        self.account_manager.edit_data_handler(entries, data, opt_in_bool, window)
        self._clear_cache()

    def popup_menu(self, event: Event) -> None:
        """
        Identify the Account that was Selected
        Args:
            event (Event): Tkinter Event Object
        """
        account_id = self.treeview.identify_row(event.y)
        if account_id:
            self.treeview.selection_set(account_id)
            try:
                self.menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.menu.grab_release()

    def refresh_tree_view(self) -> None:
        """
        Refresh Treeview
        """
        for data in self.treeview.get_children():
            self.treeview.delete(data)

    def open_file_dialog(self, entry_widget: ctk.CTkEntry) -> None:
        """
        File dialog for selecting paths
        Args:
            entry_widget (ctk.CTkEntry): Entry Widget
        """
        entry_widget.insert(0, filedialog.askopenfilename())

    def show_data(self) -> None:
        """
        Shows Data in Treeview
        """
        try:
            user_id = self.database_manager.get_user_id()
            if user_id is not None:
                if self._data_cache is None:
                    self._data_cache = self.database_manager.fetch_data()
                    encrypted_data = self._data_cache
                    self.refresh_tree_view()

                    for i, data in enumerate(encrypted_data):
                        decrypted_row = self.encryption_manager.decrypt(data[2:7])
                        self.treeview.insert(
                            "", ctk.END, values=[data[1]] + decrypted_row
                        )
                    self.data_button.configure(text="Hide Data", command=self.hide_data)
                else:
                    self.refresh_tree_view()
                    for i, data in enumerate(self._data_cache):
                        decrypted_row = self.encryption_manager.decrypt(data[2:7])
                        self.treeview.insert(
                            "", ctk.END, values=[data[1]] + decrypted_row
                        )
                    self.data_button.configure(text="Hide Data", command=self.hide_data)

        except Exception as error:
            messagebox.showerror("Error", f"Could Not Show Data: {error}")
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
