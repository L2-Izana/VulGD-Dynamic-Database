"""
NVD Validator implementation for the VulLink data pipeline.

This module provides the validator for National Vulnerability Database (NVD) data,
validating the schema and data quality.
"""

from typing import Any, Dict, List, Optional, Union

import pandas as pd
import numpy as np

from validation.base import BaseValidator
from validation.schema import Schema, SchemaField, is_valid_date, is_valid_cvss_score

class NVDValidator(BaseValidator):
    """
    Implements BaseValidator for the National Vulnerability Database (NVD).
    
    Validates the schema and data quality of processed NVD data.
    """
    
    def __init__(self):
        """
        Initialize the NVD validator.
        """
        super().__init__(source_name="NVD")
        self._define_schema()
    
    def _define_schema(self):
        """
        Define the expected schema for NVD data.
        """
        self.schema = Schema(
            name="NVD Schema",
            fields=[
                SchemaField(
                    name="cveID",
                    dtype="object",
                    required=True,
                    unique=True,
                    description="CVE identifier"
                ),
                SchemaField(
                    name="publishedDate",
                    dtype="datetime64[ns]",
                    required=True,
                    description="Date when the vulnerability was published"
                ),
                SchemaField(
                    name="description_value",
                    dtype="object",
                    required=True,
                    description="Description of the vulnerability"
                ),
                SchemaField(
                    name="num_reference",
                    dtype="int64",
                    required=False,
                    description="Number of references"
                ),
                SchemaField(
                    name="v2baseScore",
                    dtype="float64",
                    required=False,
                    validators=[is_valid_cvss_score],
                    description="CVSS v2 base score"
                ),
                SchemaField(
                    name="v3baseScore",
                    dtype="float64",
                    required=False,
                    validators=[is_valid_cvss_score],
                    description="CVSS v3 base score"
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
        # Convert column types to match expected schema
        if 'publishedDate' in df.columns and not pd.api.types.is_datetime64_any_dtype(df['publishedDate']):
            try:
                df['publishedDate'] = pd.to_datetime(df['publishedDate'])
            except:
                self.validation_errors.append("Failed to convert 'publishedDate' to datetime")
                return False
        
        if 'num_reference' in df.columns and not pd.api.types.is_integer_dtype(df['num_reference']):
            try:
                df['num_reference'] = df['num_reference'].astype('int64')
            except:
                self.validation_errors.append("Failed to convert 'num_reference' to int64")
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
        # Check required fields
        required_fields = ["cveID", "publishedDate", "description_value"]
        for field in required_fields:
            if field not in df.columns:
                self.validation_errors.append(f"Required field '{field}' is missing")
                return False
            
            null_count = df[field].isna().sum()
            if null_count > 0:
                self.validation_errors.append(f"Field '{field}' has {null_count} null values")
                return False
        
        # Check CVE IDs format
        if not df["cveID"].str.match(r"CVE-\d{4}-\d{4,7}").all():
            invalid_cves = df[~df["cveID"].str.match(r"CVE-\d{4}-\d{4,7}")]["cveID"].tolist()
            self.validation_errors.append(f"Invalid CVE IDs format: {invalid_cves[:5]} (showing max 5)")
            return False
        
        # Check CVSS scores range
        for score_field in ["v2baseScore", "v3baseScore"]:
            if score_field in df.columns:
                valid_scores = df[score_field].dropna().between(0, 10).all()
                if not valid_scores:
                    invalid_count = (~df[score_field].dropna().between(0, 10)).sum()
                    self.validation_errors.append(f"{invalid_count} {score_field} values are outside the valid range [0, 10]")
                    return False
        
        # Check for reasonable number of CVEs
        if len(df) < 10:
            self.validation_errors.append(f"Dataset contains only {len(df)} records, which is suspiciously low")
            return False
        
        self.logger.info("Data quality validation passed")
        return True 