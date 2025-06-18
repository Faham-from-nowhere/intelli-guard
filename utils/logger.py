# utils/logger.py

import logging
import os
from datetime import datetime

# Define log file path
LOG_DIR = "logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

LOG_FILE = os.path.join(LOG_DIR, f"guardian_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

def setup_logging(log_level=logging.INFO):
    """
    Sets up a basic logging configuration.
    Logs to both console and a file.
    """
    # Create a logger instance
    logger = logging.getLogger('intelligent_guardian')
    logger.setLevel(log_level)
    logger.propagate = False # Prevent logs from going to root logger if not desired

    # Clear existing handlers to avoid duplicate logs if setup is called multiple times
    if logger.handlers:
        for handler in logger.handlers:
            logger.removeHandler(handler)

    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File Handler
    file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG) # Log all levels to file
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger

# Initialize logger when module is imported
logger = setup_logging()

# You can add a function to change level dynamically if needed
def set_log_level(level):
    global logger
    logger.setLevel(level)
    for handler in logger.handlers:
        handler.setLevel(level)

if __name__ == "__main__":
    # Test logging setup
    test_logger = setup_logging(logging.DEBUG) # Set to DEBUG for testing
    test_logger.debug("This is a DEBUG message.")
    test_logger.info("This is an INFO message.")
    test_logger.warning("This is a WARNING message.")
    test_logger.error("This is an ERROR message.")
    test_logger.critical("This is a CRITICAL message.")

    print(f"\nLogs are also being written to: {LOG_FILE}")