"""
Utility module for the Neo4j migration.

This module provides helper functions and logging setup for the migration process.
"""

import os
import sys
import logging
import json
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """
    Set up logging for the migration process.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file to save logs to
        
    Returns:
        Configured logger
    """
    # Set up logging format
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Convert string log level to logging constant
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Configure logging
    logging.basicConfig(
        level=level,
        format=log_format,
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Add file handler if log file is specified
    if log_file:
        os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(log_format))
        logging.getLogger().addHandler(file_handler)
    
    # Create logger
    logger = logging.getLogger("migration")
    logger.info(f"Logging initialized with level {log_level}")
    
    return logger


def save_migration_report(report: Dict[str, Any], output_file: str) -> None:
    """
    Save migration report to a JSON file.
    
    Args:
        report: Migration report data
        output_file: Path to save the report to
    """
    # Add timestamp to report
    report["timestamp"] = datetime.now().isoformat()
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
    
    # Write report to file
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)


def check_file_exists(file_path: str) -> bool:
    """
    Check if a file exists.
    
    Args:
        file_path: Path to the file
        
    Returns:
        True if the file exists, False otherwise
    """
    return os.path.isfile(file_path)


def check_required_files(data_dir: str, required_files: List[str]) -> Tuple[bool, List[str]]:
    """
    Check if all required files exist.
    
    Args:
        data_dir: Directory containing data files
        required_files: List of required file names
        
    Returns:
        Tuple of (success boolean, list of missing files)
    """
    missing = []
    
    for file_name in required_files:
        file_path = os.path.join(data_dir, file_name)
        if not check_file_exists(file_path):
            missing.append(file_name)
    
    return len(missing) == 0, missing


def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to a human-readable string.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted duration string (e.g., "2h 30m 45s")
    """
    hours, remainder = divmod(int(seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    
    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0 or hours > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    
    return " ".join(parts)


def parse_bool(value: Any) -> bool:
    """
    Parse a boolean value from various input types.
    
    Args:
        value: Value to parse
        
    Returns:
        Boolean value
    """
    if isinstance(value, bool):
        return value
    
    if isinstance(value, str):
        return value.lower() in ("yes", "true", "t", "1", "y")
    
    return bool(value)


def create_dummy_data(filename: str, data: Dict[str, Any]) -> str:
    """
    Create a dummy data file for testing.
    
    Args:
        filename: Name of the file to create
        data: Data to write to the file
        
    Returns:
        Path to the created file
    """
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    
    return filename 