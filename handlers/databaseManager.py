import sqlite3
from typing import Optional


class DatabaseManager:
    def __init__(self, log_manager) -> None:
        """
        Manages database operations including creating, deleting, searching and editing master users and accounts.
        """
        self.db_name = "database.db"
        self.user_id = None
        self.log_manager = log_manager
        self._initiate_database()

    def connect(self) -> None:
        """
        Connects to local SQL database.
        """
        try:
            connection = sqlite3.connect(self.db_name)
            return connection
        except sqlite3.Error as e:
            self.log_manager.write_log(error_message=e)
            raise Exception(f"Failed to connect to Database: {e}")

    def _initiate_database(self) -> None:
        """
        Initializes database if it does not already exist.
        """
        try:
            with self.connect() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT UNIQUE, 
                        hash TEXT,
                        salt TEXT
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS accounts (
                        account_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        email TEXT, 
                        username TEXT, 
                        password TEXT, 
                        application TEXT, 
                        opt_in INTEGER,
                        FOREIGN KEY (user_id) REFERENCES users(user_id)
                    )
                """)
                conn.commit()
        except Exception as e:
            self.log_manager.write_log(error_message=e)

    def create_new_user(
        self,
        email: str,
        hash: bytes,
        salt: bytes,
    ) -> None:
        """
        Creates a master user by validating, hashing and saving the data.
        """
        try:
            with self.connect() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO users
                        (email, hash, salt)
                        VALUES (?, ?, ?)""",
                               (email, hash, salt),
                               )
        except sqlite3.IntegrityError:
            self.log_manager.write_log(error_message="User Already Exists.")
            raise Exception(f"User Already Exists.")
        except sqlite3.Error as e:
            self.log_manager.write_log(error_message=e)
            raise Exception(f"Failed to Insert New User Into Database: {e}")

    def search_user(self, email: str) -> Optional[tuple]:
        """
        Searches database if email already exists.
        """
        try:
            with self.connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT user_id, salt, hash FROM users WHERE email = ?", (email,))
                results = cursor.fetchone()

                if results:
                    self.user_id = results[0]
                    return results[0], bytes(results[1]), results[2]
                else:
                    self.log_manager.write_log(
                        error_message=f"No user found for email: {email}")
                    return None
        except sqlite3.Error as e:
            self.log_manager.write_log(error_message=e)
            raise Exception(f"Failed to Find User In Database: {e}")

    def fetch_data(self) -> tuple:
        """
        Retrives data based on user_id.
        """
        self.user_id = self.get_user_id()
        if self.user_id is None:
            raise Exception("User ID is not set. Cannot fetch data.")
        try:
            with self.connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM accounts WHERE user_id = ?", (self.user_id,))
                data = cursor.fetchall()
                return data
        except sqlite3.Error as e:
            self.log_manager.write_log(error_message=e)
            raise Exception(f"Failed to Fetch Data: {e}")

    def insert_account(self, data: list) -> None:
        """
        Inserts account into database.
        """
        self.user_id = self.get_user_id()
        if self.user_id is None:
            raise Exception("User ID is not set. Cannot insert account.")
        try:
            with self.connect() as conn:
                cursor = conn.cursor()
                cursor.execute("""INSERT INTO accounts (
                                    user_id, 
                                    email, 
                                    username, 
                                    password, 
                                    application, 
                                    opt_in
                                ) 
                               VALUES (?, ?, ?, ?, ?, ?)""",
                               (self.user_id, *data))
                conn.commit()
        except sqlite3.Error as e:
            self.log_manager.write_log(error_message=e)
            raise Exception(f"Failed to Insert Account Into Database: {e}")

    def update_user(
        self,
        email: str,
        hash: bytes,
        salt: bytes,
    ) -> None:
        """
        Updates users data.
        """
        try:
            with self.connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET hash = ?, salt = ? WHERE email = ?",
                    (hash, salt, email),
                )
                conn.commit()
        except sqlite3.Error as e:
            self.log_manager.write_log(error_message=e)
            raise Exception(f"Failed to Update User: {e}")
        return

    def update_account(self, account_id: int, data: list) -> None:
        """
        Updates account data.
        """
        try:
            with self.connect() as conn:
                cursor = conn.cursor()
                set_clause = ", ".join(
                    [f"{col} = ?" for col in [
                        "email", "username", "password", "application", "opt_in"]
                     ])
                query = f"UPDATE accounts SET {
                    set_clause} WHERE account_id = ?"
                cursor.execute(query, data + [account_id])
                conn.commit()
        except sqlite3.Error as e:
            self.log_manager.write_log(error_message=e)
            raise Exception(f"Failed to Update Account: {e}")

    def delete_account(self, account_id) -> None:
        """
        Deletes account based on account_id
        """
        try:
            with self.connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM accounts WHERE account_id = ?", (account_id,))
                conn.commit()
        except sqlite3.Error as e:
            self.log_manager.write_log(error_message=e)
            raise Exception(f"Failed to Delete Account From Database: {e}")

    def delete_all(self) -> None:
        """
        Deletes all accounts based on logged in user.
        """
        try:
            with self.connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM accounts WHERE user_id = ?", (self.user_id,))
                conn.commit()
        except sqlite3.Error as e:
            self.log_manager.write_log(error_message=e)
            raise Exception(f"Failed to Delete Database Table: {e}")

    def check_db_for_data(self) -> list[tuple]:
        """
        Checks for data in database.
        """
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute('PRAGMA table_info(accounts)')
            data = cursor.fetchall()
            return data

    def get_email(self, user_id: int) -> Optional[tuple]:
        """
        Retrieves email linked to user_id.
        """
        try:
            with self.connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT email FROM users WHERE user_id = ?", (user_id,))
                results = cursor.fetchone()
                return results
        except sqlite3.Error as e:
            self.log_manager.write_log(error_message=e)
            raise Exception(f"Failed to Fetch Email: {e}")

    def get_user_id(self) -> int:
        """
        Retrieves user_id for current instance.
        """
        if self.user_id is not None:
            return self.user_id
        else:
            self.log_manager.write_log(error_message="User is not logged in.")
            raise Exception("User is not logged in. Please log in first.")

    def set_user_id(self, user_id: int) -> int:
        """
        Sets user_id for current instance.
        """
        self.user_id = user_id
        return self.user_id
