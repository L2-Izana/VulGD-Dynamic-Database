"""
Pipeline module for the VulLink data pipeline.

This module provides pipeline implementations for different data sources.
"""

# Import submodules
from pipeline.simple_pipeline import run_pipeline as run_nvd_pipeline
from pipeline.simple_pipeline_cve import run_pipeline as run_cve_pipeline

__all__ = [
    'run_nvd_pipeline',
    'run_cve_pipeline',
] 