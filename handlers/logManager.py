import logging

class LogManager:
    def __init__(self):
        logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", handlers=[logging.FileHandler("./py_log.log")])
        self.logger = logging.getLogger(__name__)
        
    # Writes Error Into Log
    def write_log(self, error_message):
        self.logger.setLevel(logging.ERROR)
        self.logger.error(error_message)