from getpass import getuser
from keyring import get_password
from typing import Optional, Any

import mysql.connector
from mysql.connector import pooling
from tkinter import messagebox
from handlers.log_manager import LogManager


class DatabaseManager:
    """
    Manages database operations including creating, editing, deleting, and searching.
    """

    def __init__(self, log_manager: LogManager) -> None:
        """
        Manages database operations including creating, deleting, searching and editing master users and accounts.
        Args:
            log_manager: The Log Manager Object.
        """
        self.user_id: Optional[int] = None
        self.log_manager = log_manager
        self.db_pass = get_password("mysql", getuser())
        self.pool: Optional[pooling.MySQLConnectionPool] = None

        self.config = {
            "host": "localhost",
            "user": "root",
            "password": self.db_pass,
            "raise_on_warnings": True,
        }

        if self._check_db_exists():
            self.config["database"] = "password_manager"
            self._initiate_database_table()
            self.pool = self._create_pool()

    def _get_direct_connection(self) -> Any:
        """
        Get a direct database connection.
        Returns:
            Union[MySQLConnection, PooledMySQLConnection]: A direct connection to the MySQL database.
        """
        return mysql.connector.connect(**self.config)

    def _check_db_exists(self) -> bool:
        """
        Checks if the database exists, creates it if it doesn't.
        Returns:
            bool: True if the database exists or was created successfully, else False.
        """
        try:
            conn = self._get_direct_connection()
            cursor = conn.cursor()
            cursor.execute("SHOW DATABASES LIKE 'password_manager'")
            result = cursor.fetchone()
            if result:
                self.log_manager.log(
                    "info", "Database 'password_manager' already exists."
                )
            else:
                cursor.execute("CREATE DATABASE password_manager")
                self.log_manager.log(
                    "info", "Database 'password_manager' created successfully."
                )
            cursor.close()
            conn.close()
            return True
        except mysql.connector.Error as error:
            self.log_manager.log("error", f"Database check/creation failed: {error}")
            print(f"Database check/creation failed: {error}")
            return False

    def _create_pool(self) -> pooling.MySQLConnectionPool:
        """
        Creates MySQL Database Connection Pool of 5.
        Returns:
            MySQLConnectionPool: MySQL Database Connection Pool Object.
        """
        try:
            return pooling.MySQLConnectionPool(
                pool_name="mypool", pool_size=5, **self.config
            )
        except mysql.connector.Error as error:
            self.log_manager.log("error", f"Failed to Create Connection Pool: {error}")
            raise

    def connect(self) -> pooling.PooledMySQLConnection:
        """
        Connects to local SQL database using the connection pool.
        Returns:
            PooledMySQLConnection: Pooled SQL Connection object to the database.
        """
        if self.pool is None:
            raise Exception("Connection pool not initialized. Cannot get connection.")

        try:
            return self.pool.get_connection()
        except mysql.connector.Error as error:
            self.log_manager.log("error", f"Failed to connect to Database: {error}")
            raise

    def _initiate_database_table(self) -> None:
        """
        Initializes database tables by creating required tables if they do not already exist.
        """
        conn = None
        cursor = None
        try:
            conn = self._get_direct_connection()
            cursor = conn.cursor()
            cursor.execute("USE password_manager")

            cursor.execute(
                """
                SELECT COUNT(*) 
                FROM information_schema.tables 
                WHERE table_schema = 'password_manager' 
                AND table_name = 'users'
            """
            )

            result = cursor.fetchone()
            if result is not None and result[0] == 0:
                cursor.execute(
                    """
                    CREATE TABLE users (
                        user_id INTEGER PRIMARY KEY AUTO_INCREMENT,
                        email VARCHAR(255) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL
                    )
                """
                )
                self.log_manager.log("info", "Users table created successfully.")
            else:
                self.log_manager.log("info", "Users table already exists.")

            cursor.execute(
                """
                SELECT COUNT(*) 
                FROM information_schema.tables 
                WHERE table_schema = 'password_manager' 
                AND table_name = 'accounts'
            """
            )

            results = cursor.fetchone()
            if results is not None and results[0] == 0:
                cursor.execute(
                    """
                    CREATE TABLE accounts (
                        account_id INTEGER PRIMARY KEY AUTO_INCREMENT,
                        user_id INTEGER,
                        email VARCHAR(255),
                        username VARCHAR(255),
                        password VARCHAR(255),
                        application VARCHAR(255),
                        opt_in VARCHAR(255),
                        FOREIGN KEY (user_id) REFERENCES users(user_id)
                            ON DELETE CASCADE
                            ON UPDATE CASCADE
                    )
                """
                )
                self.log_manager.log("info", "Accounts table created successfully.")
            else:
                self.log_manager.log("info", "Accounts table already exists.")

            conn.commit()
            self.log_manager.log("info", "Database tables initialization completed.")

        except mysql.connector.Error as error:
            self.log_manager.log("error", f"Table creation failed: {error}")
            if conn:
                conn.rollback()
        finally:
            if cursor is not None:
                cursor.close()
            if conn is not None:
                conn.close()

    def create_new_user(
        self,
        email: str,
        password_hash: str,
    ) -> None:
        """
        Creates a master user.
        Master user's credentials are validated, hashed and saved into the database.
        Args:
            email (str): The email address of the user.
            password_hash (str): The Argon2 hashed password of the user.
        """
        conn = None
        cursor = None
        try:
            conn = self.connect()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users
                    (email, password_hash)
                    VALUES (%s, %s)""",
                (email, password_hash),
            )
            conn.commit()
        except mysql.connector.Error as error:
            self.log_manager.log(
                "error", f"Failed to Insert New User Into Database: {error}"
            )
            messagebox.showerror(
                "Failed to Insert New User Into Database",
                "User with that email already exists.",
            )
            raise Exception(f"Failed to Insert New User Into Database: {error}")
        finally:
            if cursor is not None:
                cursor.close()
            if conn is not None:
                conn.close()

    def search_user(self, email: str) -> tuple[int | None, str] | None:
        """
        Searches database if email already exists.
        Args:
            email (str): The email address of the user.
        Returns:
            tuple[int | None, str] | None: A tuple containing the user_id,
            and password_hash of the user if found, else None.
        """
        conn = None
        cursor = None
        try:
            conn = self.connect()
            cursor = conn.cursor(dictionary=False)
            cursor.execute(
                "SELECT user_id, password_hash FROM users WHERE email = %s",
                (email,),
            )
            results = cursor.fetchone()
            self.log_manager.log("info", f"Searching for user with email: {email}")
            if results:
                self.user_id = results[0]
                hash_raw = results[1]

                return self.user_id, hash_raw
            else:
                self.log_manager.log("error", f"No user found for email: {email}")
                return None
        except mysql.connector.Error as error:
            self.log_manager.log("error", f"Failed to Find User In Database: {error}")
            raise Exception(f"Failed to Find User In Database: {error}")
        finally:
            if cursor is not None:
                cursor.close()
            if conn is not None:
                conn.close()

    def fetch_data(self) -> list[int | str]:
        """
        Retrives data based on user_id.
        Returns:
            list[int | str]: A list of all accounts linked to the user_id.
        """
        conn = None
        cursor = None
        self.user_id = self.get_user_id()
        if self.user_id:
            try:
                conn = self.connect()
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM accounts WHERE user_id = %s", (self.user_id,)
                )
                data = cursor.fetchall()
                self.log_manager.log(
                    "info", f"Fetched data for user_id: {self.user_id}"
                )
                return data
            except mysql.connector.Error as error:
                self.log_manager.log("error", f"Failed to Fetch Data: {error}")
                raise Exception(f"Failed to Fetch Data: {error}")
            finally:
                if cursor is not None:
                    cursor.close()
                if conn is not None:
                    conn.close()
        else:
            self.log_manager.log("error", "User ID is not set.")
            raise Exception("User ID is not set. Cannot fetch data.")

    def insert_account(self, data: list[int | str]) -> None:
        """
        Inserts account into database.
        Args:
            data (list[int | str]): List of account data to be inserted.
        """
        conn = None
        cursor = None
        self.user_id = self.get_user_id()
        if not self.user_id:
            raise Exception("User ID is not set. Cannot insert account.")
        try:
            conn = self.connect()
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO accounts (
                                user_id,
                                email,
                                username,
                                password,
                                application,
                                opt_in
                            )
                            VALUES (%s, %s, %s, %s, %s, %s)""",
                (self.user_id, *data),
            )
            conn.commit()
        except mysql.connector.Error as error:
            self.log_manager.log(
                "error", f"Failed to Insert Account Into Database: {error}"
            )
            raise Exception(f"Failed to Insert Account Into Database: {error}")
        finally:
            if cursor is not None:
                cursor.close()
            if conn is not None:
                conn.close()

    def update_user(
        self,
        email: str,
        password_hash: str,
    ) -> None:
        """
        Updates users data.
        Args:
            email (str): The email address of the user.
            password_hash (str): The Argon2 hashed password of the user.
        """
        conn = None
        cursor = None
        try:
            conn = self.connect()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET password_hash = %s WHERE email = %s",
                (password_hash, email),
            )
            conn.commit()
        except mysql.connector.Error as error:
            self.log_manager.log("Error", f"Failed to Update User: {error}")
            raise Exception(f"Failed to Update User: {error}")
        finally:
            if cursor is not None:
                cursor.close()
            if conn is not None:
                conn.close()

    def update_account(self, account_id: int, data: list[int | str]) -> None:
        """
        Updates account data.
        Args:
            account_id (int): The account_id of the account to be updated.
            data (list[int | str]): List of account data to be updated
        """
        conn = None
        cursor = None
        try:
            conn = self.connect()
            cursor = conn.cursor()
            set_clause = ", ".join(
                [
                    f"{col} = %s"
                    for col in [
                        "email",
                        "username",
                        "password",
                        "application",
                        "opt_in",
                    ]
                ]
            )
            query = f"UPDATE accounts SET {set_clause} WHERE account_id = %s"
            cursor.execute(query, data + [account_id])
            conn.commit()
        except mysql.connector.Error as error:
            self.log_manager.log("error", f"Failed to Update Account: {error}")
            raise Exception(f"Failed to Update Account: {error}")
        finally:
            if cursor is not None:
                cursor.close()
            if conn is not None:
                conn.close()

    def delete_account(self, account_id: int) -> int | None:
        """
        Deletes account based on account_id
        Args:
            account_id: The account_id of the account to be deleted.
        Returns:
            int | None: The number of rows if found, else None.
        """
        conn = None
        cursor = None
        try:
            conn = self.connect()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM accounts WHERE account_id = %s", (account_id,))
            conn.commit()
            return cursor.rowcount
        except mysql.connector.Error as error:
            self.log_manager.log(
                "error", f"Failed to Delete Account From Database: {error}"
            )
            raise Exception(f"Failed to Delete Account From Database: {error}")
        finally:
            if cursor is not None:
                cursor.close()
            if conn is not None:
                conn.close()

    def delete_all_accounts(self) -> int | None:
        """
        Deletes all accounts based on the logged-in user.
        Returns:
            int | None: The number of rows deleted if found, else None.
        """
        if self.user_id is None:
            raise Exception("User ID is not set. Cannot delete accounts.")

        conn = None
        cursor = None
        try:
            conn = self.connect()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM accounts WHERE user_id = %s", (self.user_id,))
            conn.commit()
            return cursor.rowcount
        except mysql.connector.Error as error:
            if conn:
                conn.rollback()
            self.log_manager.log("error", f"Failed to Delete Database Table: {error}")
            raise Exception(f"Failed to Delete Database Table: {error}")
        finally:
            if cursor is not None:
                cursor.close()
            if conn is not None:
                conn.close()

    def check_db_for_data(self) -> bool:
        """
        Checks for the existence of data in the 'accounts' table and returns bool.
        Returns:
            bool: True if data exists, else False.
        """
        conn = None
        cursor = None
        try:
            conn = self.connect()
            cursor = conn.cursor()

            cursor.execute(
                "SELECT * FROM accounts where user_id = %s LIMIT 1", (self.user_id,)
            )
            has_data = cursor.fetchone()
        except mysql.connector.Error as error:
            self.log_manager.log("error", f"Failed to Check Database for Data: {error}")
            raise Exception(f"Failed to Check Database for Data: {error}")
        finally:
            if cursor is not None:
                cursor.close()
            if conn is not None:
                conn.close()

        return bool(has_data)

    def get_email(self, user_id: int) -> tuple[str] | None:
        """
        Retrieves email linked to user_id.
        Args:
            user_id (int): The user_id of the user.
        Returns:
            tuple[str] | None: A tuple containing the email of the user if found, else None.
        """
        conn = None
        cursor = None
        try:
            conn = self.connect()
            cursor = conn.cursor()
            cursor.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
            results = cursor.fetchone()
            if results:
                return tuple(results)
        except mysql.connector.Error as error:
            self.log_manager.log("error", f"Failed to Fetch Email: {error}")
            raise Exception(f"Failed to Fetch Email: {error}")
        finally:
            if cursor is not None:
                cursor.close()
            if conn is not None:
                conn.close()

    def get_user_id(self) -> int:
        """
        Retrieves user_id for current instance.
        Returns:
            int: The user_id of the current
        """
        if self.user_id:
            return self.user_id
        else:
            self.log_manager.log("warning", "User is not logged in.")
            raise Exception("User is not logged in. Please log in first.")

    def set_user_id(self, user_id: int) -> int:
        """
        Sets user_id for current instance.
        Args:
            user_id (int): The user_id of the user.
        Returns:
            int: The user_id of the current instance.
        """
        self.user_id = user_id
        return self.user_id
