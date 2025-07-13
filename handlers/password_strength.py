import os
from math import log2
import string

from handlers.log_manager import LogManager


class PasswordStrength:
    """
    Manages Password Strength Tests & Checks if User's Password is in Pwned List.
    """

    def __init__(self):
        """
        Fetches and Caches the Pwned Password List
        """
        self.log_manager = LogManager()
        file_path = "./assets/wordlists/password_list.txt"
        try:
            with open(file_path, "r") as f:
                self.pwned_passwords = set(f.read().splitlines())
                self.log_manager.log("info", "Pwned Passwords list loaded to cache.")
        except FileNotFoundError:
            self.pwned_passwords = set()
            self.log_manager.log(
                "error", "Pwned Passwords list file not found. No passwords loaded."
            )

    def check_pwned(self, password: str) -> bool:
        """
        Checks if the given password is in the Pwned Passwords list.
        Args:
            password (str): The password to check.
        Returns:
            bool: True if the password is pwned, False otherwise.
        """
        return password in self.pwned_passwords

    def calculate_entropy(self, password: str) -> int:
        """
        Creates a set of possible characters in a given password.
        Calculates and returns the entropy of given password.

        Args:
            password (str): Given password to calculate the entropy.

        Returns:
            entropy (int): Calculated entropy of the password.
        """
        password_length = len(password)
        char_categories = {
            "alpha": 26 if any(i.isalpha() for i in password) else 0,
            "digit": 10 if any(i.isdigit() for i in password) else 0,
            "punctuation": 40 if any(i in string.punctuation for i in password) else 0,
        }

        character_set = sum(char_categories.values())
        entropy = int(log2(character_set) * password_length) if character_set > 0 else 0
        return entropy
