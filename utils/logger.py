"""
Thread-safe logging configuration with console and rotating file support.
"""
import os
import logging
from logging.handlers import RotatingFileHandler
from config.constants import DIR_LOGS

def setup_logger(name: str = "security_platform") -> logging.Logger:
    logger = logging.getLogger(name)
    
    # If logger handlers are already set up, reuse them
    if logger.handlers:
        return logger
        
    logger.setLevel(logging.DEBUG)
    
    # Ensure logs directory exists
    os.makedirs(DIR_LOGS, exist_ok=True)
    log_file_path = os.path.join(DIR_LOGS, "security_platform.log")
    
    # Formatter
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [%(threadName)s] [%(filename)s:%(lineno)d]: %(message)s'
    )
    
    # Console Handler (Only INFO and higher)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    
    # Rotating File Handler (All logs starting from DEBUG, max 5MB, keeps last 5 logs)
    file_handler = RotatingFileHandler(
        log_file_path,
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Add handlers to the logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger

# Globally accessible logger instance
logger = setup_logger()
