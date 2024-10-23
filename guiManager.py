from tkinter import Menu, messagebox, ttk, filedialog
import tkinter as tk
import ttkbootstrap as tb
from databaseManager import DatabaseManager
from encryptionManager import EncryptionManager
from accountManager import AccountManager
from passwordGenerator import PasswordGenerator
from emailManager import EmailManager


class GUIManager:
    def __init__(self, main_window):
        self.main_window = main_window
        self.db_manager = DatabaseManager()
        self.encryption_manager = EncryptionManager()
        self.password_generator = PasswordGenerator(self.main_window)
        self.email_manager = EmailManager()
        self.account_manager = None
        
        self.style = tb.Style()
        self.style.theme_use("cyborg")
        self.columns = ["ID", "Email", "Username", "Password", "Application"]
        
        self.build_main_window()


    # Initializes the AccountManager class and sets up dependencies
    def initialize_account_manager(self):
        self.ui_manager = self
        self.account_manager = AccountManager(self.main_window, self.db_manager, self.encryption_manager, self.ui_manager, self.email_manager)

    
    # Get Data From Selected Row
    def get_selected(self, action="edit"):
        selected = self.tree.selection()
        if selected:
            dict_data = self.tree.item(selected)
            selected_data = dict_data["values"]

        if action == "edit":
            self.edit_account(selected_data)
        if action == "delete":
            self.account_manager.delete_account(selected_data)


    # Create Main Window
    def build_main_window(self):
        self.initialize_account_manager()
        self.tree = ttk.Treeview(self.main_window, columns=self.columns, show="headings", selectmode="browse")
        self.menu = Menu(self.main_window, tearoff=False)
        self.tree.bind('<Button-3>', self.popup_menu)
        self.menu.add_command(label="Edit", command=lambda : self.get_selected(action="edit"))
        self.menu.add_command(label="Delete", command=lambda : self.get_selected(action="delete"))

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
        self.new_pass_button = tk.Button(self.button_tree, text="Password Generator", command=self.show_generator_window)
        self.add_button = tk.Button(self.button_tree, text="Add Account", command=self.add_account)
        self.data_button = tk.Button(self.button_tree, text="Show Data", command=self.show_data)
        self.delete_button = tk.Button(self.button_tree, text="Delete All Data", command=self.account_manager.delete_all)

        self.new_pass_button.pack(side=tk.BOTTOM)
        self.add_button.pack(side=tk.LEFT, pady=5)
        self.data_button.pack(side=tk.LEFT, pady=5)
        self.delete_button.pack(side=tk.LEFT, pady=5)


    # Create New Account Window 
    def add_account(self):
        self.new_account_window = tk.Toplevel(self.main_window)
        self.new_account_window.attributes('-topmost', True)
        self.new_account_window.geometry("280x150")
        self.new_account_window.resizable(False, False)
        self.new_account_window.title("Add Account")

        self.all_entry = []
        for i, label in enumerate(self.columns[1:]):
            tk.Label(self.new_account_window, text=label).grid(row=i, column=0)
            self.entry = tk.Entry(self.new_account_window, width=25)
            if i == 2:  # Hide password entry
                self.entry.config(show='*')
            self.entry.grid(row=i, column=1)
            self.all_entry.append(self.entry)

        e1_button = tk.Button(self.new_account_window, text="Add Path", command=lambda: self.open_file_dialog(self.all_entry[3]))
        e1_button.grid(row=3, column=2, columnspan=1)

        self.opt_in_bool = tk.IntVar()
        opt_in_checkbox = tk.Checkbutton(self.new_account_window, text="Opt in for newsletters!", variable=self.opt_in_bool, onvalue=1, offvalue=0)
        opt_in_checkbox.grid(row=4, column=1, columnspan=1)

        submit_button = tk.Button(self.new_account_window, text="Submit", 
                                  command=lambda: self.is_entry_empty(self.all_entry))
        submit_button.grid(row=5, column=1, columnspan=1)


    # Highlight Empty Entry Wigits
    def is_entry_empty(self, entry):
        entry_filled = True
        for i in entry:
            if not i.get():
                i.config(highlightthickness=2, highlightbackground = "red", highlightcolor= "red")
                entry_filled = False
        
        if entry_filled:
            self.account_manager.new_data_handler(self.all_entry, self.opt_in_bool, self.new_account_window)


    # Edit Account Window
    def edit_account(self, data):
        if not data:
            return
        edit_account_window = tk.Toplevel(self.main_window)
        edit_account_window.geometry("300x150")
        edit_account_window.attributes('-topmost', True)
        edit_account_window.resizable(False, False)
        edit_account_window.title("Edit Account")

        edit_entries = []
        for i, label in enumerate(self.columns[1:]):
            tk.Label(edit_account_window, text=label).grid(row=i, column=0)
            entry = tk.Entry(edit_account_window, width=30)
            entry.insert(0, data[i + 1])
            entry.grid(row=i, column=1)
            edit_entries.append(entry)

        opt_in_bool = tk.IntVar(value=data[5])
        opt_in_checkbox = tk.Checkbutton(edit_account_window, text="Opt in for newsletters!", variable=opt_in_bool, onvalue=1, offvalue=0)
        opt_in_checkbox.grid(row=7, column=1, columnspan=1)

        submit_button = tk.Button(edit_account_window, text="Submit", command=lambda: self.account_manager.edit_data_handler(edit_entries, data, opt_in_bool, edit_account_window))
        submit_button.grid(row=8, column=1, columnspan=1)
    

    # Identify the Account that was Selected
    def popup_menu(self, event):
        account_id = self.tree.identify_row(event.y)
        if account_id:
            self.tree.selection_set(account_id)
            try:
                self.menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.menu.grab_release()


    # Refresh Treeview
    def refresh_tree_view(self):
        for data in self.tree.get_children():
            self.tree.delete(data)


    # File dialog for selecting paths
    def open_file_dialog(self, entry_widget):
        entry_widget.insert(0, filedialog.askopenfilename())

    # Reveals Treeview Data
    def show_data(self):
        try:
            encrypted_data = self.db_manager.fetch_data()
            decrypted_data = [self.encryption_manager.decrypt(data) for data in encrypted_data]
            self.refresh_tree_view()
            for data in decrypted_data:
                self.tree.insert("", tk.END, values=data)
            self.data_button.configure(text="Hide Data", command=self.hide_data)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.delete_button.configure(state="disabled")
            self.data_button.configure(state="disabled")

    
    # Hides Treeview Data 
    def hide_data(self):
        self.refresh_tree_view()
        self.data_button.configure(text="Show Data", command=self.show_data)
        return
    

    # Creates Password Generator Window
    def show_generator_window(self):
        self.pwd_gen_window = tk.Toplevel(self.main_window)
        self.pwd_gen_window.geometry("450x150")
        self.pwd_gen_window.attributes('-topmost', True)
        self.pwd_gen_window.resizable(False, False)
        self.pwd_gen_window.title("Password Generator")

        style = tb.Style()
        style.theme_use("cyborg")
        password_length = tk.IntVar(value=16)
        
        entry = tk.Entry(self.pwd_gen_window, width=30)
        slider = tk.Scale(self.pwd_gen_window, variable=password_length, from_=8, to=24, orient="horizontal", sliderlength=15, length=100)
        slider_value = tk.Label(self.pwd_gen_window, textvariable=password_length)
        slider.set(16)
        
        option_special = tk.Checkbutton(self.pwd_gen_window, text="Include Special Characters?", variable=self.password_generator.include_special, command=self.password_generator.update_alphabet)
        option_caps = tk.Checkbutton(self.pwd_gen_window, text="Include Uppercase Letters?", variable=self.password_generator.include_caps, command=self.password_generator.update_alphabet)
        option_numbers = tk.Checkbutton(self.pwd_gen_window, text="Include Numbers?", variable=self.password_generator.include_numbers, command=self.password_generator.update_alphabet)
        

        # Updates Generated Password Entry
        def on_generate():
            password = self.password_generator.generate_password(password_length.get())
            entry.delete(0, tk.END)
            entry.insert(0, password)


        generate_pwd_button = tk.Button(self.pwd_gen_window, text="Generate Password", command=on_generate)
        
        entry.grid(row=1, column=3, padx=25, pady=15, sticky="s")
        slider.grid(row=2, column=3, sticky="n")
        slider_value.grid(row=3, column=3, sticky="n")
        generate_pwd_button.grid(row=4, column=3, sticky="n")
        option_special.grid(row=2, column=5, columnspan=2, sticky="w")
        option_caps.grid(row=3, column=5, columnspan=2, sticky="w")
        option_numbers.grid(row=4, column=5, columnspan=2, sticky="w")