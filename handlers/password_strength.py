from math import log2
import string
import requests


class PasswordStrength:
    """
    Manages Password Strength Tests & Checks if User's Password is in Pwned List.
    """

    def __init__(self):
        """
        Fetches and Caches the Pwned Password list for O(1) Time Complexity.
        """
        self.pwned_passwords = self._fetch_pwned_passwords()

    def _fetch_pwned_passwords(self) -> set:
        """
        Fetch and return the list of pwned passwords as a set.
        """
        url = (
            "https://www.ncsc.gov.uk/static-assets/documents/PwnedPasswordsTop100k.json"
        )
        try:
            response = requests.get(url)
            response.raise_for_status()
            return set(response.json())
        except requests.exceptions.RequestException as e:
            print(f"Error fetching pwned passwords: {e}")
            return set()

    def check_pwned_list(self, password: str) -> bool:
        """
        Checks if given password is in pwned password list.
        Args:
            password (str): Given password to check.

        Returns:
            bool: True if password in set. False otherwise.
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
