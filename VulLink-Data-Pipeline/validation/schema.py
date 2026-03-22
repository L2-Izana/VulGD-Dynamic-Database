"""
Schema validation utilities for the VulLink data pipeline.

This module provides functions and classes for defining and validating
data schemas across different data sources.
"""

from typing import Any, Dict, List, Optional, Set, Union, Callable
import pandas as pd
import numpy as np

class SchemaField:
    """
    Represents a field in a data schema with validation rules.
    """
    
    def __init__(
        self, 
        name: str, 
        dtype: Any, 
        required: bool = True,
        unique: bool = False,
        validators: Optional[List[Callable[[Any], bool]]] = None,
        description: str = ""
    ):
        """
        Initialize a schema field.
        
        Args:
            name (str): Field name
            dtype (Any): Expected data type
            required (bool, optional): Whether the field is required. Defaults to True.
            unique (bool, optional): Whether values must be unique. Defaults to False.
            validators (List[Callable], optional): List of validation functions. Defaults to None.
            description (str, optional): Field description. Defaults to "".
        """
        self.name = name
        self.dtype = dtype
        self.required = required
        self.unique = unique
        self.validators = validators or []
        self.description = description
    
    def validate(self, series: pd.Series) -> List[str]:
        """
        Validate a pandas Series against this field's rules.
        
        Args:
            series (pd.Series): The data to validate
            
        Returns:
            List[str]: List of validation error messages, empty if valid
        """
        errors = []
        
        # Check data type
        if not pd.api.types.is_dtype_equal(series.dtype, self.dtype):
            errors.append(f"Field '{self.name}' has incorrect dtype: expected {self.dtype}, got {series.dtype}")
        
        # Check for nulls if required
        if self.required and series.isna().any():
            null_count = series.isna().sum()
            errors.append(f"Field '{self.name}' has {null_count} null values but is required")
        
        # Check uniqueness
        if self.unique and not series.is_unique:
            duplicate_count = len(series) - len(series.unique())
            errors.append(f"Field '{self.name}' has {duplicate_count} duplicate values but should be unique")
        
        # Run custom validators
        for validator in self.validators:
            try:
                # Apply validator to non-null values
                if not series.dropna().apply(validator).all():
                    errors.append(f"Field '{self.name}' failed custom validation")
            except Exception as e:
                errors.append(f"Field '{self.name}' validation error: {str(e)}")
        
        return errors


class Schema:
    """
    Represents a complete data schema with multiple fields.
    """
    
    def __init__(self, fields: List[SchemaField], name: str = ""):
        """
        Initialize a schema.
        
        Args:
            fields (List[SchemaField]): List of schema fields
            name (str, optional): Schema name. Defaults to "".
        """
        self.fields = {field.name: field for field in fields}
        self.name = name
    
    def validate(self, df: pd.DataFrame) -> List[str]:
        """
        Validate a DataFrame against this schema.
        
        Args:
            df (pd.DataFrame): The DataFrame to validate
            
        Returns:
            List[str]: List of validation error messages, empty if valid
        """
        errors = []
        
        # Check for required fields
        required_fields = {name for name, field in self.fields.items() if field.required}
        missing_fields = required_fields - set(df.columns)
        if missing_fields:
            errors.append(f"Missing required fields: {', '.join(missing_fields)}")
        
        # Validate each field
        for field_name, field in self.fields.items():
            if field_name in df.columns:
                field_errors = field.validate(df[field_name])
                errors.extend(field_errors)
        
        return errors


# Common validators
def is_positive(value):
    """Check if a value is positive."""
    return value > 0

def is_valid_date(value):
    """Check if a value is a valid date."""
    return pd.notna(value) and isinstance(value, (pd.Timestamp, np.datetime64))

def is_valid_url(value):
    """Check if a value is a valid URL."""
    if not isinstance(value, str):
        return False
    return value.startswith(('http://', 'https://'))

def is_valid_cvss_score(value):
    """Check if a value is a valid CVSS score (0.0-10.0)."""
    if not isinstance(value, (int, float)):
        return False
    return 0.0 <= value <= 10.0 