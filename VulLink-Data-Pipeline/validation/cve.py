"""
CVE Validator implementation for the VulLink data pipeline.

This module provides the validator for Common Vulnerabilities and Exposures (CVE) data,
validating the schema and data quality.
"""

from typing import Any, Dict, List, Optional, Union
import re

import pandas as pd
import numpy as np

from validation.base import BaseValidator
from validation.schema import Schema, SchemaField

class CVEValidator(BaseValidator):
    """
    Implements BaseValidator for Common Vulnerabilities and Exposures (CVE) data.
    
    Validates the schema and data quality of processed CVE data, particularly
    the mapping between CVE IDs and ExploitDB IDs.
    """
    
    def __init__(self):
        """
        Initialize the CVE validator.
        """
        super().__init__(source_name="CVE")
        self._define_schema()
    
    def _define_schema(self):
        """
        Define the expected schema for CVE data.
        """
        self.schema = Schema(
            name="CVE Schema",
            fields=[
                SchemaField(
                    name="ExploitID",
                    dtype="object",
                    required=True,
                    description="ExploitDB identifier"
                ),
                SchemaField(
                    name="cveID",
                    dtype="object",
                    required=True,
                    description="CVE identifier"
                )
            ]
        )
    
    def validate_schema(self, df: pd.DataFrame) -> bool:
        """
        Validate that the DataFrame has the expected schema.
        
        Args:
            df (pd.DataFrame): The DataFrame to validate
            
        Returns:
            bool: True if the schema is valid, False otherwise
        """
        # Check if required columns exist
        required_columns = {"ExploitID", "cveID"}
        if not required_columns.issubset(set(df.columns)):
            missing_columns = required_columns - set(df.columns)
            self.validation_errors.append(f"Missing required columns: {missing_columns}")
            return False
        
        # Validate against the schema
        errors = self.schema.validate(df)
        if errors:
            self.validation_errors.extend(errors)
            self.logger.warning(f"Schema validation failed with {len(errors)} errors")
            return False
        
        self.logger.info("Schema validation passed")
        return True
    
    def validate_data_quality(self, df: pd.DataFrame) -> bool:
        """
        Validate the quality of the data.
        
        Args:
            df (pd.DataFrame): The DataFrame to validate
            
        Returns:
            bool: True if the data quality is acceptable, False otherwise
        """
        # Check for null values
        for col in ["ExploitID", "cveID"]:
            if col in df.columns and df[col].isna().any():
                null_count = df[col].isna().sum()
                self.validation_errors.append(f"Column '{col}' has {null_count} null values")
                return False
        
        # Validate CVE ID format
        if "cveID" in df.columns:
            cve_pattern = r"^CVE-\d{4}-\d{4,7}$"
            valid_cve_format = df["cveID"].str.match(cve_pattern).all()
            if not valid_cve_format:
                invalid_count = (~df["cveID"].str.match(cve_pattern)).sum()
                self.validation_errors.append(f"{invalid_count} CVE IDs do not match the expected format (CVE-YYYY-NNNN...)")
                return False
        
        # Validate ExploitDB ID format
        if "ExploitID" in df.columns:
            edb_pattern = r"^EDB-\d+$"
            valid_edb_format = df["ExploitID"].str.match(edb_pattern).all()
            if not valid_edb_format:
                invalid_count = (~df["ExploitID"].str.match(edb_pattern)).sum()
                self.validation_errors.append(f"{invalid_count} ExploitDB IDs do not match the expected format (EDB-NNNNN)")
                return False
        
        # Check for reasonable number of entries
        if len(df) < 10:
            self.validation_errors.append(f"Dataset contains only {len(df)} records, which is suspiciously low")
            return False
        
        self.logger.info("Data quality validation passed")
        return True 