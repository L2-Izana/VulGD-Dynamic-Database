"""
CVE Preprocessor implementation for the VulLink data pipeline.

This module provides the preprocessor for Common Vulnerabilities and Exposures (CVE) data,
cleaning and structuring the data for further processing.
"""

import csv
import os
import re
from typing import Any, Dict, List, Optional, Union

import pandas as pd
import numpy as np

from preprocessing.base import BasePreprocessor

class CVEPreprocessor(BasePreprocessor):
    """
    Implements BasePreprocessor for the Common Vulnerabilities and Exposures (CVE) data.
    
    Parses and cleans CVE data, particularly the mapping between CVE IDs and ExploitDB IDs.
    """
    
    def __init__(self, input_dir: str, output_dir: Optional[str] = None):
        """
        Initialize the CVE preprocessor.
        
        Args:
            input_dir (str): Directory containing raw CVE data files
            output_dir (str, optional): Directory to store processed data. If None, uses input_dir.
        """
        super().__init__(source_name="CVE", input_dir=input_dir, output_dir=output_dir)
    
    def load_raw_data(self, file_path: str) -> List[List[str]]:
        """
        Load raw CVE data from CSV file.
        
        Args:
            file_path (str): Path to the CSV file
            
        Returns:
            List[List[str]]: List of rows from the CSV file
        """
        try:
            data = []
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                for row in reader:
                    data.append(row)
            
            self.logger.info(f"Loaded {len(data)} rows from {file_path}")
            return data
        except Exception as e:
            self.logger.error(f"Error loading raw data from {file_path}: {e}")
            raise
    
    def process_data(self, data: List[List[str]]) -> pd.DataFrame:
        """
        Process the raw CVE data into a structured DataFrame.
        
        Args:
            data (List[List[str]]): The raw CVE data
            
        Returns:
            pd.DataFrame: The processed data as a pandas DataFrame
        """
        # Check if data has a header
        if not data:
            self.logger.error("Empty data received")
            return pd.DataFrame()
        
        header = data[0]
        rows = data[1:]
        
        # Convert to pandas DataFrame
        df = pd.DataFrame(rows, columns=header)
        
        # Process CVE IDs (they might be semicolon-separated)
        if 'cveID' in df.columns:
            # Explode multiple CVE IDs into separate rows
            df_exploded = df.assign(cveID=df['cveID'].str.split(';')).explode('cveID')
            
            # Clean up CVE IDs: remove whitespace and empty strings
            df_exploded['cveID'] = df_exploded['cveID'].str.strip()
            df_exploded = df_exploded[df_exploded['cveID'] != '']
            
            # Normalize the CVE IDs to a standard format (CVE-YYYY-NNNN)
            df_exploded['cveID'] = df_exploded['cveID'].apply(self._normalize_cve_id)
            
            # Remove rows with invalid CVE IDs
            df_exploded = df_exploded[df_exploded['cveID'].notna()]
            
            self.logger.info(f"Processed {len(df)} exploit entries into {len(df_exploded)} CVE-Exploit mappings")
            return df_exploded
        else:
            self.logger.warning("Column 'cveID' not found in data")
            return pd.DataFrame(rows, columns=header)
    
    def _normalize_cve_id(self, cve_id: str) -> Optional[str]:
        """
        Normalize a CVE ID to the standard format CVE-YYYY-NNNN.
        
        Args:
            cve_id (str): CVE ID to normalize
            
        Returns:
            Optional[str]: Normalized CVE ID, or None if invalid
        """
        # Check if already in standard format
        if pd.isna(cve_id) or not isinstance(cve_id, str):
            return None
        
        # Clean up the CVE ID
        cve_id = cve_id.strip().upper()
        
        # Check if it's already in the standard format
        if re.match(r'^CVE-\d{4}-\d{4,7}$', cve_id):
            return cve_id
        
        # Try to extract year and number
        match = re.search(r'(?:CVE)?-?(\d{4})-(\d{4,7})', cve_id)
        if match:
            year, number = match.groups()
            return f"CVE-{year}-{number}"
        
        return None
    
    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean the processed CVE data.
        
        Args:
            df (pd.DataFrame): The processed data
            
        Returns:
            pd.DataFrame: The cleaned data
        """
        # Make a copy to avoid modifying the original
        cleaned_df = df.copy()
        
        # Clean ExploitID: ensure it starts with 'EDB-'
        if 'ExploitID' in cleaned_df.columns:
            # Add 'EDB-' prefix if not present
            cleaned_df['ExploitID'] = cleaned_df['ExploitID'].apply(
                lambda x: f"EDB-{x}" if isinstance(x, str) and not x.startswith('EDB-') else x
            )
            
            # Remove non-numeric exploits after the prefix
            cleaned_df = cleaned_df[cleaned_df['ExploitID'].str.slice(4).str.isnumeric()]
        
        # Drop duplicates
        initial_count = len(cleaned_df)
        cleaned_df.drop_duplicates(inplace=True)
        duplicate_count = initial_count - len(cleaned_df)
        self.logger.info(f"Removed {duplicate_count} duplicate entries")
        
        return cleaned_df 