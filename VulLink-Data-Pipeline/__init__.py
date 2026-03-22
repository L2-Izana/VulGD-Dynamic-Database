"""
VulLink Data Pipeline Package.

This package provides tools for collecting, processing, validating, and storing
vulnerability data from various sources.
"""

# Make submodules available for import
from . import crawling
from . import preprocessing
from . import validation
from . import migration
from . import pipeline

# Import key functions and classes
from config import SOURCES, DB_CONFIG
from logger import get_logger, setup_logger
from utils import get_session, download_file

__all__ = [
    'crawling',
    'preprocessing',
    'validation', 
    'migration',
    'pipeline',
    'SOURCES',
    'DB_CONFIG',
    'get_logger',
    'setup_logger',
    'get_session',
    'download_file',
] 