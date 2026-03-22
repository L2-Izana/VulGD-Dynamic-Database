"""
Base Preprocessor class for the VulLink data pipeline.

This module defines the abstract base class that all preprocessor implementations must follow
to maintain a consistent interface across different data sources.
"""

from abc import ABC, abstractmethod
import os
import time
from typing import Any, Dict, List, Optional, Union

import pandas as pd

from logger import get_logger

class BasePreprocessor(ABC):
    """
    Abstract base class for all data source preprocessors.
    
    This class defines the interface that all preprocessor implementations must follow,
    providing common functionality and enforcing a consistent structure.
    """
    
    def __init__(self, source_name: str, input_dir: str, output_dir: Optional[str] = None):
        """
        Initialize the base preprocessor.
        
        Args:
            source_name (str): Name of the data source
            input_dir (str): Directory containing raw data files
            output_dir (str, optional): Directory to store processed data.
                                      If None, uses input_dir.
        """
        self.source_name = source_name
        self.input_dir = input_dir
        self.output_dir = output_dir if output_dir else input_dir
        self.logger = get_logger(f"preprocessing.{source_name.lower()}")
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.logger.info(f"Initialized {source_name} preprocessor")
    
    @abstractmethod
    def load_raw_data(self, file_path: str) -> Any:
        """
        Load raw data from a file.
        
        Args:
            file_path (str): Path to the raw data file
            
        Returns:
            Any: The loaded raw data
        """
        pass
    
    @abstractmethod
    def process_data(self, data: Any) -> pd.DataFrame:
        """
        Process the raw data into a structured format.
        
        Args:
            data (Any): The raw data to process
            
        Returns:
            pd.DataFrame: The processed data as a pandas DataFrame
        """
        pass
    
    @abstractmethod
    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean the processed data.
        
        Args:
            df (pd.DataFrame): The processed data
            
        Returns:
            pd.DataFrame: The cleaned data
        """
        pass
    
    def save_processed_data(self, df: pd.DataFrame, file_path: str) -> None:
        """
        Save the processed data to a file.
        
        Args:
            df (pd.DataFrame): The processed data
            file_path (str): The path to save the data to
        """
        # Ensure directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        # Save data based on file extension
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext == '.csv':
            df.to_csv(file_path, index=False)
        elif file_ext == '.pkl':
            df.to_pickle(file_path)
        else:
            df.to_csv(file_path, index=False)
        
        self.logger.info(f"Saved processed data to {file_path}")
    
    def run(self, input_file: str, output_file: str) -> str:
        """
        Run the full preprocessing process.
        
        Args:
            input_file (str): Name of the input file
            output_file (str): Name of the output file
            
        Returns:
            str: Path to the saved processed data file
        """
        start_time = time.time()
        self.logger.info(f"Starting {self.source_name} preprocessing")
        
        # Create full file paths
        input_path = os.path.join(self.input_dir, input_file)
        output_path = os.path.join(self.output_dir, output_file)
        
        try:
            # Load raw data
            self.logger.info(f"Loading raw data from {input_path}")
            raw_data = self.load_raw_data(input_path)
            
            # Process data
            self.logger.info("Processing data")
            processed_df = self.process_data(raw_data)
            
            # Clean data
            self.logger.info("Cleaning data")
            cleaned_df = self.clean_data(processed_df)
            
            # Validate that we have a DataFrame with data
            assert isinstance(cleaned_df, pd.DataFrame), "Cleaned data must be a pandas DataFrame"
            assert not cleaned_df.empty, "Cleaned DataFrame cannot be empty"
            
            # Save processed data
            self.logger.info(f"Saving processed data to {output_path}")
            self.save_processed_data(cleaned_df, output_path)
            
            elapsed_time = time.time() - start_time
            self.logger.info(f"Completed {self.source_name} preprocessing in {elapsed_time:.2f} seconds")
            
            return output_path
        except Exception as e:
            self.logger.error(f"Error during preprocessing: {e}", exc_info=True)
            raise 