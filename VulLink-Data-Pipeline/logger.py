"""
Logging configuration for the VulLink pipeline.

This module sets up logging for all components of the pipeline to ensure
consistent log formats and output destinations.
"""

import logging
import os
from datetime import datetime
from pathlib import Path

from config import LOGS_DIR


def setup_logger(name, log_file=None, level=logging.INFO):
    """
    Set up a logger with the specified name, file, and level.
    
    Args:
        name (str): Name of the logger
        log_file (str, optional): Path to the log file. If None, logs are only sent to console.
        level (int, optional): Logging level. Defaults to logging.INFO.
        
    Returns:
        logging.Logger: Configured logger instance
    """
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Create file handler if log_file is specified
    if log_file:
        # Ensure the logs directory exists
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(module_name):
    """
    Get a logger for a specific module with appropriate file name.
    
    Args:
        module_name (str): The module name (e.g., 'crawler.nvd', 'processor.cve')
        
    Returns:
        logging.Logger: Configured logger instance
    """
    date_str = datetime.now().strftime('%Y-%m-%d')
    log_file = os.path.join(LOGS_DIR, f"{date_str}_{module_name.replace('.', '_')}.log")
    return setup_logger(f"vullink.{module_name}", log_file) 