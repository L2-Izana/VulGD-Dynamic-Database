"""
Base Validator class for the VulLink data pipeline.

This module defines the abstract base class that all validator implementations must follow
to maintain a consistent interface across different data sources.
"""

from abc import ABC, abstractmethod
import os
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import pandas as pd

from logger import get_logger

class BaseValidator(ABC):
    """
    Abstract base class for all data validators.
    
    This class defines the interface that all validator implementations must follow,
    providing common functionality and enforcing a consistent structure.
    """
    
    def __init__(self, source_name: str):
        """
        Initialize the base validator.
        
        Args:
            source_name (str): Name of the data source
        """
        self.source_name = source_name
        self.logger = get_logger(f"validation.{source_name.lower()}")
        self.validation_errors = []
        
        self.logger.info(f"Initialized {source_name} validator")
    
    @abstractmethod
    def validate_schema(self, df: pd.DataFrame) -> bool:
        """
        Validate that the DataFrame has the expected schema.
        
        Args:
            df (pd.DataFrame): The DataFrame to validate
            
        Returns:
            bool: True if the schema is valid, False otherwise
        """
        pass
    
    @abstractmethod
    def validate_data_quality(self, df: pd.DataFrame) -> bool:
        """
        Validate the quality of the data.
        
        Args:
            df (pd.DataFrame): The DataFrame to validate
            
        Returns:
            bool: True if the data quality is acceptable, False otherwise
        """
        pass
    
    def validate_data_consistency(self, df: pd.DataFrame) -> bool:
        """
        Validate the consistency of the data.
        
        Args:
            df (pd.DataFrame): The DataFrame to validate
            
        Returns:
            bool: True if the data is consistent, False otherwise
        """
        # Check for duplicates
        duplicates = df.duplicated().sum()
        if duplicates > 0:
            self.validation_errors.append(f"Found {duplicates} duplicate rows")
            self.logger.warning(f"Found {duplicates} duplicate rows")
            return False
        
        return True
    
    def run(self, df: pd.DataFrame) -> Tuple[bool, List[str]]:
        """
        Run all validations on the DataFrame.
        
        Args:
            df (pd.DataFrame): The DataFrame to validate
            
        Returns:
            Tuple[bool, List[str]]: A tuple containing:
                - bool: True if all validations passed, False otherwise
                - List[str]: List of validation errors
        """
        start_time = time.time()
        self.logger.info(f"Starting {self.source_name} validation")
        self.validation_errors = []
        
        # Validate that we have a DataFrame with data
        if not isinstance(df, pd.DataFrame):
            self.validation_errors.append("Input is not a pandas DataFrame")
            return False, self.validation_errors
        
        if df.empty:
            self.validation_errors.append("DataFrame is empty")
            return False, self.validation_errors
        
        # Run all validations
        schema_valid = self.validate_schema(df)
        quality_valid = self.validate_data_quality(df)
        consistency_valid = self.validate_data_consistency(df)
        
        # Determine overall validation result
        validation_passed = all([schema_valid, quality_valid, consistency_valid])
        
        elapsed_time = time.time() - start_time
        if validation_passed:
            self.logger.info(f"All validations passed in {elapsed_time:.2f} seconds")
        else:
            self.logger.warning(f"Validation failed with {len(self.validation_errors)} errors in {elapsed_time:.2f} seconds")
            for error in self.validation_errors:
                self.logger.warning(f"Validation error: {error}")
        
        return validation_passed, self.validation_errors 