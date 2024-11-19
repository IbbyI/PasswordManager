import logging


class LogManager:
    def __init__(self) -> None:
        """
        Handles error logging and saves to file.
        """
        logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s",
                            handlers=[
                                logging.FileHandler("./py_log.log"),
                            ])
        self.logger = logging.getLogger(__name__)

    def write_log(self, error_message: str) -> None:
        self.logger.setLevel(logging.ERROR)
        self.logger.error(error_message)
