import secrets
import string
import tkinter as tk

import pyperclip


class PasswordGenerator:
    def __init__(self, main_window) -> None:
        self.main_window = main_window
        self.alphabet = list(string.ascii_lowercase)
        self.include_special = tk.BooleanVar()
        self.include_caps = tk.BooleanVar()
        self.include_numbers = tk.BooleanVar()

    def update_alphabet(self) -> None:
        """
        Updates Alphabet Based on User Requests
        """
        self.alphabet = list(string.ascii_lowercase)
        if self.include_caps.get():
            self.alphabet += list(string.ascii_uppercase)
        if self.include_special.get():
            self.alphabet += list(string.punctuation)
        if self.include_numbers.get():
            self.alphabet += list(string.digits)

    def generate_password(self, length: int) -> str:
        """
        Generates Random Password Using Given Alphabet
        """
        password = "".join(secrets.choice(self.alphabet) for _ in range(length))
        pyperclip.copy(password)
        return password
