"""
NVD Preprocessor implementation for the VulLink data pipeline.

This module provides the preprocessor for National Vulnerability Database (NVD) data,
parsing the JSON files into a structured DataFrame and performing data cleaning.
"""

import json
import os
import re
from typing import Any, Dict, List, Optional, Union

import pandas as pd
import numpy as np
from datetime import datetime

from preprocessing.base import BasePreprocessor

class NVDPreprocessor(BasePreprocessor):
    """
    Implements BasePreprocessor for the National Vulnerability Database (NVD).
    
    Parses NVD JSON files into a structured DataFrame, extracts relevant information,
    and performs data cleaning.
    """
    
    def __init__(self, input_dir: str, output_dir: Optional[str] = None):
        """
        Initialize the NVD preprocessor.
        
        Args:
            input_dir (str): Directory containing raw NVD JSON files
            output_dir (str, optional): Directory to store processed data. If None, uses input_dir.
        """
        super().__init__(source_name="NVD", input_dir=input_dir, output_dir=output_dir)
    
    def load_raw_data(self, file_path: str) -> Dict[str, Any]:
        """
        Load the NVD JSON file metadata or a single NVD JSON file.
        
        Args:
            file_path (str): Path to the metadata file or a JSON file
            
        Returns:
            Dict[str, Any]: The loaded JSON data or metadata
        """
        try:
            with open(file_path, 'r', errors='ignore') as f:
                data = json.load(f)
            
            # Check if this is a metadata file or a direct JSON file
            if "json_files" in data:
                # This is a metadata file, load the actual JSON files
                json_files = data["json_files"]
                self.logger.info(f"Loaded metadata with {len(json_files)} JSON files")
                
                combined_data = {"CVE_Items": []}
                for json_file in json_files:
                    if os.path.exists(json_file):
                        with open(json_file, 'r', errors='ignore') as f:
                            file_data = json.load(f)
                            combined_data["CVE_Items"].extend(file_data.get("CVE_Items", []))
                
                self.logger.info(f"Loaded {len(combined_data['CVE_Items'])} CVE items from JSON files")
                return combined_data
            else:
                # This is a direct JSON file
                return data
                
        except Exception as e:
            self.logger.error(f"Error loading raw data from {file_path}: {e}")
            raise
    
    def process_data(self, data: Dict[str, Any]) -> pd.DataFrame:
        """
        Process the raw NVD JSON data into a structured DataFrame.
        
        Args:
            data (Dict[str, Any]): The raw NVD data
            
        Returns:
            pd.DataFrame: The processed data as a pandas DataFrame
        """
        cve_items = data.get('CVE_Items', [])
        rows = []
        
        for item in cve_items:
            try:
                cve = item.get('cve', {})
                meta = cve.get('CVE_data_meta', {})
                impact = item.get('impact', {})
                
                cve_id = meta.get('ID')
                published_date = item.get('publishedDate')
                description_data = cve.get('description', {}).get('description_data', [])
                description_value = description_data[0].get('value') if description_data else None
                num_ref = len(cve.get('references', {}).get('reference_data', []))
                
                # Extract CVSS v2 metrics
                base_metric_v2 = impact.get('baseMetricV2', {})
                cvss_v2 = base_metric_v2.get('cvssV2', {})
                
                v2version = cvss_v2.get('version')
                v2baseScore = cvss_v2.get('baseScore')
                v2accessVector = cvss_v2.get('accessVector')
                v2accessComplexity = cvss_v2.get('accessComplexity')
                v2authentication = cvss_v2.get('authentication')
                v2confidentialityImpact = cvss_v2.get('confidentialityImpact')
                v2integrityImpact = cvss_v2.get('integrityImpact')
                v2availabilityImpact = cvss_v2.get('availabilityImpact')
                v2vectorString = cvss_v2.get('vectorString')
                
                v2impactScore = base_metric_v2.get('impactScore')
                v2exploitabilityScore = base_metric_v2.get('exploitabilityScore')
                v2userInteractionRequired = base_metric_v2.get('userInteractionRequired')
                v2severity = base_metric_v2.get('severity')
                v2obtainUserPrivilege = cvss_v2.get('obtainUserPrivilege')
                v2obtainAllPrivilege = cvss_v2.get('obtainAllPrivilege')
                v2acInsufInfo = cvss_v2.get('acInsufInfo')
                v2obtainOtherPrivilege = cvss_v2.get('obtainOtherPrivilege')
                
                # Extract CVSS v3 metrics
                base_metric_v3 = impact.get('baseMetricV3', {})
                cvss_v3 = base_metric_v3.get('cvssV3', {})
                
                v3version = cvss_v3.get('version')
                v3baseScore = cvss_v3.get('baseScore')
                v3attackVector = cvss_v3.get('attackVector')
                v3attackComplexity = cvss_v3.get('attackComplexity')
                v3privilegesRequired = cvss_v3.get('privilegesRequired')
                v3userInteraction = cvss_v3.get('userInteraction')
                v3scope = cvss_v3.get('scope')
                v3confidentialityImpact = cvss_v3.get('confidentialityImpact')
                v3integrityImpact = cvss_v3.get('integrityImpact')
                v3availabilityImpact = cvss_v3.get('availabilityImpact')
                v3vectorString = cvss_v3.get('vectorString')
                
                v3impactScore = base_metric_v3.get('impactScore')
                v3exploitabilityScore = base_metric_v3.get('exploitabilityScore')
                v3baseSeverity = cvss_v3.get('baseSeverity')
                
                rows.append({
                    'cveID': cve_id,
                    'publishedDate': published_date,
                    'description_value': description_value,
                    'num_reference': num_ref,
                    'v2version': v2version,
                    'v2baseScore': v2baseScore,
                    'v2accessVector': v2accessVector,
                    'v2accessComplexity': v2accessComplexity,
                    'v2authentication': v2authentication,
                    'v2confidentialityImpact': v2confidentialityImpact,
                    'v2integrityImpact': v2integrityImpact,
                    'v2availabilityImpact': v2availabilityImpact,
                    'v2vectorString': v2vectorString,
                    'v2impactScore': v2impactScore,
                    'v2exploitabilityScore': v2exploitabilityScore,
                    'v2userInteractionRequired': v2userInteractionRequired,
                    'v2severity': v2severity,
                    'v2obtainUserPrivilege': v2obtainUserPrivilege,
                    'v2obtainAllPrivilege': v2obtainAllPrivilege,
                    'v2acInsufInfo': v2acInsufInfo,
                    'v2obtainOtherPrivilege': v2obtainOtherPrivilege,
                    'v3version': v3version,
                    'v3baseScore': v3baseScore,
                    'v3attackVector': v3attackVector,
                    'v3attackComplexity': v3attackComplexity,
                    'v3privilegesRequired': v3privilegesRequired,
                    'v3userInteraction': v3userInteraction,
                    'v3scope': v3scope,
                    'v3confidentialityImpact': v3confidentialityImpact,
                    'v3integrityImpact': v3integrityImpact,
                    'v3availabilityImpact': v3availabilityImpact,
                    'v3vectorString': v3vectorString,
                    'v3impactScore': v3impactScore,
                    'v3exploitabilityScore': v3exploitabilityScore,
                    'v3baseSeverity': v3baseSeverity,
                })
            except Exception as e:
                self.logger.warning(f"Error processing CVE item: {e}")
        
        df = pd.DataFrame(rows)
        self.logger.info(f"Processed {len(df)} CVE items into DataFrame")
        return df
    
    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean the processed NVD data.
        
        Args:
            df (pd.DataFrame): The processed data
            
        Returns:
            pd.DataFrame: The cleaned data
        """
        # Make a copy to avoid modifying the original
        cleaned_df = df.copy()
        
        # Remove REJECT and DISPUTED entries
        if 'description_value' in cleaned_df.columns:
            initial_count = len(cleaned_df)
            
            # Remove entries with REJECT in the description
            mask_reject = cleaned_df['description_value'].str.slice(0, 15).str.contains('REJECT', na=False)
            cleaned_df = cleaned_df[~mask_reject]
            
            # Remove entries with DISPUTED in the description
            mask_disputed = cleaned_df['description_value'].str.slice(0, 15).str.contains('DISPUTED', na=False)
            cleaned_df = cleaned_df[~mask_disputed]
            
            removed_count = initial_count - len(cleaned_df)
            self.logger.info(f"Removed {removed_count} REJECT/DISPUTED entries")
        
        # Convert publishedDate to datetime
        if 'publishedDate' in cleaned_df.columns and not cleaned_df['publishedDate'].empty:
            cleaned_df['publishedDate'] = pd.to_datetime(
                cleaned_df['publishedDate'], 
                format='%Y-%m-%dT%H:%MZ',
                errors='coerce'
            )
        
        # Drop duplicates
        initial_count = len(cleaned_df)
        cleaned_df.drop_duplicates(subset=['cveID'], inplace=True)
        duplicate_count = initial_count - len(cleaned_df)
        self.logger.info(f"Removed {duplicate_count} duplicate entries")
        
        return cleaned_df 