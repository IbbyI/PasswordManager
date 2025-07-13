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
        self.pwd_gen_window.geometry("800x390")
        self.pwd_gen_window.attributes("-topmost", True)
        self.pwd_gen_window.resizable(False, False)
        self.pwd_gen_window.title("Password Generator")
        self.pwd_gen_window.configure(
            bg_color="#242424",
            fg_color="#242424",
        )

        pwd_gen_frame = ctk.CTkFrame(
            self.pwd_gen_window, fg_color="#242424", bg_color="#242424"
        )

        options_frame = ctk.CTkFrame(
            self.pwd_gen_window, fg_color="#242424", bg_color="#242424"
        )

        pwd_gen_frame.pack(side="top", pady=10, padx=10)
        options_frame.pack(side="bottom", pady=10, padx=10)

        self.include_special = ctk.BooleanVar()
        self.include_caps = ctk.BooleanVar()
        self.include_numbers = ctk.BooleanVar()

        password_length = ctk.IntVar(value=16)

        entry = ctk.CTkEntry(
            pwd_gen_frame,
            width=250,
            height=50,
            font=("Arial", 25),
            placeholder_text="Generated Password",
        )

        slider = ctk.CTkSlider(
            pwd_gen_frame,
            from_=8,
            to=24,
            orientation="horizontal",
            number_of_steps=16,
            width=200,
            height=20,
            command=lambda value: password_length.set(int(value)),
        )
        slider_value = ctk.CTkLabel(
            pwd_gen_frame, font=("Arial", 25), textvariable=password_length
        )
        slider.set(password_length.get())

        option_special = ctk.CTkCheckBox(
            options_frame,
            text="Include Special Characters?",
            variable=self.include_special,
            command=self.update_alphabet,
            font=("Arial", 28),
        )
        option_caps = ctk.CTkCheckBox(
            options_frame,
            text="Include Uppercase Letters?",
            variable=self.include_caps,
            command=self.update_alphabet,
            font=("Arial", 28),
        )
        option_numbers = ctk.CTkCheckBox(
            options_frame,
            text="Include Numbers?",
            variable=self.include_numbers,
            command=self.update_alphabet,
            font=("Arial", 28),
        )

        def on_generate(event=None) -> None:
            """
            Updates Generated Password Entry
            """
            password = self.generate_password(password_length.get())
            entry.delete(0, ctk.END)
            entry.insert(0, password)

        generate_pwd_button = ctk.CTkButton(
            pwd_gen_frame,
            text="Generate Password",
            command=on_generate,
            font=("Arial", 25),
            width=250,
            height=50,
        )
        self.pwd_gen_window.bind("<Return>", on_generate)

        entry.pack(side="top", padx=10, pady=2)
        slider.pack(side="top", padx=10, pady=10)
        slider_value.pack(side="top", padx=10, pady=2)
        generate_pwd_button.pack(side="top", padx=10, pady=15)

        option_special.pack(side="top", padx=10, pady=2)
        option_caps.pack(side="top", padx=10, pady=2)
        option_numbers.pack(side="top", padx=10, pady=2)
