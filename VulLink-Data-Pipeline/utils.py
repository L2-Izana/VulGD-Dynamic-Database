"""
Utility functions for the VulLink data pipeline.

This module provides common utility functions that can be used across
different components of the data pipeline.
"""

import os
import hashlib
import json
import pickle
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
import pandas as pd
import numpy as np
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from pathlib import Path

from config import TIMEOUT, RETRIES
from logger import get_logger
    
logger = get_logger("utils")

def get_session():
    """
    Create a requests session with retry capability.
    
    Returns:
        requests.Session: Configured session object
    """
    session = requests.Session()
    retry = Retry(
        total=RETRIES,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def download_file(url: str, output_path: str, session: Optional[requests.Session] = None) -> str:
    """
    Download a file from a URL to a local path.
    
    Args:
        url (str): URL to download
        output_path (str): Local path to save file
        session (requests.Session, optional): Requests session. Creates new one if None.
        
    Returns:
        str: Path to downloaded file
    """
    if session is None:
        session = get_session()
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Download the file
    logger.info(f"Downloading {url} to {output_path}")
    response = session.get(url, stream=True, timeout=TIMEOUT)
    response.raise_for_status()
    
    with open(output_path, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    
    logger.info(f"Successfully downloaded {url} to {output_path}")
    return output_path

def compute_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """
    Compute the hash of a file.
    
    Args:
        file_path (str): Path to the file
        algorithm (str, optional): Hash algorithm to use. Defaults to 'sha256'.
        
    Returns:
        str: Hex digest of the hash
    """
    hash_obj = hashlib.new(algorithm)
    with open(file_path, 'rb') as f:
        # Read and update hash in chunks for large files
        for chunk in iter(lambda: f.read(4096), b''):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

def save_checkpoint(data: Any, file_path: str) -> None:
    """
    Save checkpoint data to a file.
    
    Args:
        data (Any): Data to save
        file_path (str): Path to save the data to
    """
    directory = os.path.dirname(file_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    
    # Determine format based on file extension
    ext = os.path.splitext(file_path)[1].lower()
    if ext == '.json':
        with open(file_path, 'w') as f:
            json.dump(data, f)
    elif ext == '.pkl':
        with open(file_path, 'wb') as f:
            pickle.dump(data, f)
    else:
        # Default to pickle
        with open(file_path, 'wb') as f:
            pickle.dump(data, f)
    
    logger.info(f"Saved checkpoint to {file_path}")

def load_checkpoint(file_path: str) -> Any:
    """
    Load checkpoint data from a file.
    
    Args:
        file_path (str): Path to the checkpoint file
        
    Returns:
        Any: The loaded data
    """
    if not os.path.exists(file_path):
        logger.warning(f"Checkpoint file {file_path} does not exist")
        return None
    
    # Determine format based on file extension
    ext = os.path.splitext(file_path)[1].lower()
    if ext == '.json':
        with open(file_path, 'r') as f:
            data = json.load(f)
    elif ext == '.pkl':
        with open(file_path, 'rb') as f:
            data = pickle.load(f)
    else:
        # Default to pickle
        try:
            with open(file_path, 'rb') as f:
                data = pickle.load(f)
        except Exception:
            logger.error(f"Failed to load checkpoint from {file_path}")
            return None
    
    logger.info(f"Loaded checkpoint from {file_path}")
    return data

def get_current_timestamp() -> str:
    """
    Get the current timestamp as a string.
    
    Returns:
        str: Current timestamp in format YYYYMMDD_HHMMSS
    """
    return datetime.now().strftime('%Y%m%d_%H%M%S')

def generate_random_user_agent() -> str:
    """
    Generate a random user agent string.
    
    Returns:
        str: Random user agent string
    """
    user_agents = [
        'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7',
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:30.0) Gecko/20100101 Firefox/30.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/537.75.14",
        "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Win64; x64; Trident/6.0)",
        'Mozilla/5.0 (Windows; U; Windows NT 5.1; it; rv:1.8.1.11) Gecko/20071127 Firefox/2.0.0.11',
        'Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.5 (like Gecko) (Kubuntu)',
        'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:10.0) Gecko/20100101 Firefox/10.0',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36',
    ]
    return np.random.choice(user_agents)

def data_summary(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Generate a summary of a DataFrame.
    
    Args:
        df (pd.DataFrame): The DataFrame to summarize
        
    Returns:
        Dict[str, Any]: Dictionary with summary statistics
    """
    summary = {
        'shape': df.shape,
        'columns': list(df.columns),
        'null_counts': df.isna().sum().to_dict(),
        'memory_usage': df.memory_usage(deep=True).sum(),
        'duplicate_rows': df.duplicated().sum(),
    }
    
    # Add numeric column statistics
    numeric_cols = df.select_dtypes(include=np.number).columns
