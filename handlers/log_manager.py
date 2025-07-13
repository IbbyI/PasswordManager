import logging
from pathlib import Path


class LogManager:
    """
    LogManager class is used to log messages to a file and console.
    """

    def __init__(self, log_file: str = "./logs/app.log") -> None:
        """
        Initialize the LogManager with a log file.
        Args:
            log_file: The path to the log file.
        """
        Path("./logs/").mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger("PasswordManager")
        self.logger.setLevel(logging.DEBUG)

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )
        self.logger.addHandler(file_handler)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        self.logger.addHandler(console_handler)

    def log(self, level: str, message: str) -> None:
        """
        Log messages to the file and console.
        Args:
            level (str): The log level.
            message (str): The message to be logged.
        """
        if level == "info":
            self.logger.info(message)
        elif level == "warning":
            self.logger.warning(message)
        elif level == "debug":
            self.logger.debug(message)
        else:
            self.logger.error(message)
