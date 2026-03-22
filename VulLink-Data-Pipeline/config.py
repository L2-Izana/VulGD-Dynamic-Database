"""
Configuration settings for the VulLink pipeline.

This module contains all configuration settings for the data pipeline including paths,
database connection details, and source-specific configurations.
"""

import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent  # VulLink project root
# print(BASE_DIR)
DATA_DIR = os.path.join(BASE_DIR, "datasource")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

# Create directories if they don't exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# Chrome driver path
CHROME_DRIVER_PATH = os.path.join(BASE_DIR, "drivers/chromedriver.exe")

# Source-specific configurations
SOURCES = {
    "NVD": {
        "output_dir": os.path.join(DATA_DIR, "NVD"),
        "url": "https://nvd.nist.gov/vuln/data-feeds",
        "recent_file": "VulnerabilityNodes-recent.csv",
        "main_file": "VulnerabilityNodes.csv",
    },
    "CVE": {
        "output_dir": os.path.join(DATA_DIR, "CVE"),
        "url": "http://cve.mitre.org/data/refs/refmap/source-EXPLOIT-DB.html",
        "output_file": "CVEdata.csv",
    },
    "ExploitDB": {
        "output_dir": os.path.join(DATA_DIR, "ExploitDB"),
        "output_file": "ExploitDBdata.csv",
        "starting_page": 1,
    },
    "CWE": {
        "output_dir": os.path.join(DATA_DIR, "CWE"),
        "url": "https://cwe.mitre.org/data/definitions/1000.html",
        "output_file": "CWEdata.csv",
    },
    "CVEDetails": {
        "output_dir": os.path.join(DATA_DIR, "CVEdetails"),
        "url": "https://www.cvedetails.com/",
        "output_file": "CVEDetailsdata.csv",
    }
}

# Database configuration
DB_CONFIG = {
    "neo4j": {
        "uri": "bolt://localhost:7687",
        "user": "neo4j",
        "password": "your_password",
    }
}

# Processing configurations
BATCH_SIZE = 1000
MAX_WORKERS = 4  # For parallel processing
TIMEOUT = 30  # Request timeout in seconds
RETRIES = 3  # Number of retries for failed requests

# Scheduled updates (24-hour format)
SCHEDULE = {
    "recent_updates": "02:00",  # 2 AM daily
    "yearly_updates": "03:00",  # 3 AM daily
} 