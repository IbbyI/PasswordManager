import secrets
import string
import pyperclip
import customtkinter as ctk


class PasswordGenerator:
    """
    Manages Password Generation.
    """

    def __init__(self) -> None:
        """
        Initialize the PasswordGenerator.
        """
        self.alphabet = list(string.ascii_lowercase)
        self.include_special = None
        self.include_caps = None
        self.include_numbers = None
        self.pwd_gen_window = None

    def update_alphabet(self) -> None:
        """
        Updates Alphabet Based on User Requests
        """
        self.alphabet = list(string.ascii_lowercase)
        if self.include_caps and self.include_caps.get():
            self.alphabet += list(string.ascii_uppercase)
        if self.include_special and self.include_special.get():
            self.alphabet += list(string.punctuation)
        if self.include_numbers and self.include_numbers.get():
            self.alphabet += list(string.digits)

    def generate_password(self, length: int) -> str:
        """
        Generates Random Password Using Given Alphabet
        Args:
            length (int): Length of the password.
        Returns:
            str: Random Password
        """
        password = "".join(secrets.choice(self.alphabet) for _ in range(length))
        pyperclip.copy(password)
        return password

    def generate_window(self) -> None:
        """
        Creates Password Generator Window
        """
        if self.pwd_gen_window is not None and self.pwd_gen_window.winfo_exists():
            self.pwd_gen_window.focus()
            return

        self.pwd_gen_window = ctk.CTkToplevel()
        self.pwd_gen_window.focus()
        self.pwd_gen_window.geometry("450x150")
        self.pwd_gen_window.attributes("-topmost", True)
        self.pwd_gen_window.resizable(False, False)
        self.pwd_gen_window.title("Password Generator")

        self.include_special = ctk.BooleanVar()
        self.include_caps = ctk.BooleanVar()
        self.include_numbers = ctk.BooleanVar()

        password_length = ctk.IntVar(value=16)

        entry = ctk.CTkEntry(self.pwd_gen_window, width=180)
        slider = ctk.CTkSlider(
            self.pwd_gen_window,
            command=lambda value: password_length.set(int(value)),
            from_=8,
            to=24,
            orientation="horizontal",
            number_of_steps=16,
        )
        slider_value = ctk.CTkLabel(self.pwd_gen_window, textvariable=password_length)
        slider.set(password_length.get())

        option_special = ctk.CTkCheckBox(
            self.pwd_gen_window,
            text="Include Special Characters?",
            variable=self.include_special,
            command=self.update_alphabet,
        )
        option_caps = ctk.CTkCheckBox(
            self.pwd_gen_window,
            text="Include Uppercase Letters?",
            variable=self.include_caps,
            command=self.update_alphabet,
        )
        option_numbers = ctk.CTkCheckBox(
            self.pwd_gen_window,
            text="Include Numbers?",
            variable=self.include_numbers,
            command=self.update_alphabet,
        )

        def on_generate(event=None) -> None:
            """
            Updates Generated Password Entry
            """
            password = self.generate_password(password_length.get())
            entry.delete(0, ctk.END)
            entry.insert(0, password)

        generate_pwd_button = ctk.CTkButton(
            self.pwd_gen_window, text="Generate Password", command=on_generate
        )
        self.pwd_gen_window.bind("<Return>", on_generate)

        entry.grid(row=1, column=3, padx=25, pady=15, sticky="s")
        slider.grid(row=2, column=3, sticky="n")
        slider_value.grid(row=3, column=3, sticky="n")
        generate_pwd_button.grid(row=4, column=3, sticky="n")
        option_special.grid(row=2, column=5, columnspan=2, sticky="w")
        option_caps.grid(row=3, column=5, columnspan=2, sticky="w")
        option_numbers.grid(row=4, column=5, columnspan=2, sticky="w")
