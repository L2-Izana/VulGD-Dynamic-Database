# VulLink Data Pipeline

A comprehensive data pipeline for collecting, processing, validating, and storing vulnerability data from multiple sources.

## Overview

The VulLink data pipeline collects vulnerability data from sources such as:
- National Vulnerability Database (NVD)
- Common Vulnerabilities and Exposures (CVE)
- Common Weakness Enumeration (CWE)
- Exploit Database (ExploitDB)

The pipeline follows a four-stage process:
1. **Crawling**: Data collection from sources
2. **Preprocessing**: Data cleaning and transformation
3. **Validation**: Data quality and schema validation
4. **Migration**: Loading data into a Neo4j database

## Architecture

The pipeline is organized into modular components:

```
VulLink-Data-Pipeline/
├── pipeline/               # Core pipeline implementation
├── crawling/               # Data collection modules
├── preprocessing/          # Data transformation modules
├── validation/             # Data validation modules
├── migration/              # Database migration modules
├── drivers/                # Web drivers for crawling
├── config.py               # Configuration settings
├── logger.py               # Logging functionality
├── run_pipeline.py         # CLI entry point
└── utils.py                # Utility functions
```

## Running the Pipeline

Run the pipeline using the command line interface:

```bash
# Run the full NVD pipeline
python run_pipeline.py nvd

# Run the full CVE pipeline
python run_pipeline.py cve

# Run specific stages of the NVD pipeline
python run_pipeline.py nvd --stages crawl preprocess

# Run specific stages of the CVE pipeline
python run_pipeline.py cve --stages validate migrate
```

## Data Flow

The data flows through the pipeline as follows:

1. **Crawling**: Raw data is collected and saved to the `raw` directory for each source.
2. **Preprocessing**: Raw data is transformed and saved to the `processed` directory.
3. **Validation**: Processed data is validated and saved to the `validated` directory.
4. **Migration**: Validated data is loaded into the Neo4j database.

## Configuration

Configure the pipeline in `config.py`:
- Data source URLs and output directories
- Database connection details
- Processing settings (batch size, timeout, etc.)

## Requirements

- Python 3.6+
- Selenium WebDriver (for dynamic crawling)
- Neo4j database
- Packages: pandas, requests, beautifulsoup4, neo4j, etc.