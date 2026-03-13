# VulLink: A Dynamic Knowledge Graph for Vulnerability Intelligence

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Architecture](#project-architecture)
- [Implementation Process](#implementation-process)
- [Directory Structure](#directory-structure)
- [Installation & Setup](#installation--setup)
- [Usage](#usage)
  - [Deploying the Neo4j Browser](#deploying-the-neo4j-browser)
  - [Loading Vulnerability Data](#loading-vulnerability-data)
  - [Pipeline Management](#pipeline-management)
- [Future Enhancements](#future-enhancements)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Overview

**VulLink** is a dynamic knowledge graph designed for vulnerability intelligence.

### Our Contribution:

- **Dynamic Knowledge Graph:** Developed VulLink, integrating real-time data on vulnerabilities and exploits, accessible to the research community.
- **Leveraging LLMs:** Used LLMs to enhance vulnerability descriptions, aiding in tasks like exploitability prediction and exploitation time forecasting.
- **Risk Assessment Use Cases:** Demonstrated VulLink's effectiveness in identifying high-risk vulnerabilities, predicting exploitation patterns, and improving patch prioritization.

## Features

- **Automated Environment Setup:** Provisions an AWS EC2 instance with all required dependencies.
- **Neo4j Deployment:** Installs and configures the Neo4j Browser for interactive data exploration.
- **Data Ingestion Pipeline:** Loads vulnerability data into the Neo4j graph database.
- **Pipeline Management:** Provides scripts for managing data processing tasks.
- **Extensible Framework:** Modular design allows for future integration with additional data sources.

## Project Architecture

- **`init_ec2_stable.sh`** – Configures the EC2 instance with the necessary packages and dependencies.
- **`deploy_neo4j_browser.sh`** – Installs and sets up the Neo4j Browser.
- **`load_data.sh`** – Loads vulnerability data into the Neo4j database.
- **`start_pipeline.sh` & `stop_pipeline.sh`** – Scripts designed for future automated pipeline management.

## Implementation Process

1. **Conceptualization and Design:**
   - **Idea Formation:** Designed to map vulnerabilities using a graph structure for better analysis.
   - **Architecture Planning:** Chose AWS EC2 for compute stability and Neo4j for graph-based visualization.
   - **Modular Approach:** Developed discrete scripts for each task.

2. **Environment Setup:**
   - **EC2 Initialization:** Created `init_ec2_stable.sh` to provision and configure the EC2 instance.
   - **Automation:** Reduced manual intervention by automating dependency installations and configurations.

3. **Service Deployment:**
   - **Neo4j Browser Deployment:** Developed `deploy_neo4j_browser.sh` to install and configure the Neo4j Browser.
   - **Data Loading Pipeline:** Implemented `load_data.sh` to ingest vulnerability data into Neo4j, including error handling and logging.

4. **Pipeline Control:**
   - **Management Scripts:** Added `start_pipeline.sh` and `stop_pipeline.sh` as placeholders for future automated pipeline management.
   - **Testing and Iteration:** Each component was tested individually before integration into the full pipeline.

## Directory Structure

```
VulLink/
├── README.md
├── scripts/
│   ├── deploy_neo4j_browser.sh  # Deploys and configures the Neo4j Browser
│   ├── init_ec2_stable.sh       # Initializes the EC2 instance with dependencies
│   ├── load_data.sh             # Loads vulnerability data into the Neo4j database
│   ├── start_pipeline.sh        # (Placeholder) Starts the data processing pipeline
│   └── stop_pipeline.sh         # (Placeholder) Stops the data processing pipeline
└── ... (other project files)
```

## Installation & Setup

### Prerequisites:

- An active AWS account with EC2 access.
- SSH access to your EC2 instance.
- Basic knowledge of Bash scripting and Linux command-line operations.
- (Optional) [Neo4j](https://neo4j.com/) installed locally for testing.

### Clone the Repository:

```bash
git clone https://github.com/yourusername/VulLink.git
cd VulLink
```

### Configure Your Environment:

Adjust configuration parameters (e.g., EC2 instance details, Neo4j credentials) in the scripts as needed. Ensure your AWS credentials are properly configured.

```bash
# Initialize the EC2 instance
cd scripts
./init_ec2_stable.sh

# Deploy the customized Neo4j Browser
./deploy_neo4j_browser.sh

# Load Vulnerability Data
./load_data.sh

# Enable dynamic data pipeline
./start_pipeline.sh
```

## Future Enhancements

- **Pipeline Orchestration:** Implement detailed start/stop procedures with scheduling and monitoring.
- **Data Validation & Error Handling:** Enhance error handling in `load_data.sh` for improved data integrity.
- **User Interface Enhancements:** Refine the Neo4j Browser deployment for a better user experience.
- **Extended Data Sources:** Integrate additional sources of vulnerability data and enhance correlation logic.

## Contributing

Contributions are welcome! To contribute:

1. **Fork the repository**
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them with clear messages.
4. Submit a pull request for review.
5. For major changes, please open an issue first to discuss your proposed modifications.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for full details.

## Contact

For inquiries, suggestions, or contributions, contact us at [dodinhluat6@gmail.com](mailto:dodinhluat6@gmail.com), [21760427@students.ltu.edu.au](mailto:21760427@students.ltu.edu.au) or open an issue on GitHub.

# VulLink Pipeline

A modular pipeline for collecting, processing, validating, and migrating vulnerability data from various sources.

## Structure

The pipeline consists of four main modules:

1. **Crawling** - Downloads data from vulnerability sources
2. **Preprocessing** - Cleans and structures the raw data
3. **Validation** - Validates the processed data schema and quality
4. **Migration** - Inserts the data into the Neo4j database

Each module implements the specific logic for different data sources:
- NVD (National Vulnerability Database)
- CVE (Common Vulnerabilities and Exposures)
- ExploitDB
- CWE (Common Weakness Enumeration)
- CVEDetails

## Installation

1. Clone this repository
2. Install the package in development mode:
   ```
   pip install -e .
   ```

## Usage

The package provides simple scripts to run the pipeline for specific data sources:

```bash
# Run the full NVD pipeline
python -m pipeline.run_pipeline nvd

# Run only specific stages of the CVE pipeline
python -m pipeline.run_pipeline cve --stages crawl preprocess
```

### Options

- `source`: The data source to process (`nvd` or `cve`)
- `--stages`: The pipeline stages to run (any combination of `crawl`, `preprocess`, `validate`, `migrate`)

## Configuration

Edit the configuration in each simple pipeline script:

- `simple_pipeline.py` for NVD data
- `simple_pipeline_cve.py` for CVE data

You'll need to update the database connection details:

```python
DB_CONFIG = {
    "uri": "bolt://localhost:7687",
    "user": "neo4j",
    "password": "your_password",
}
```

## Adding More Data Sources

To add a new data source:

1. Implement the required classes in each module:
   - `crawling/new_source.py`
   - `preprocessing/new_source.py`
   - `validation/new_source.py`
   - `migration/new_source.py`

2. Create a new pipeline script:
   - `simple_pipeline_new_source.py`

3. Update `run_pipeline.py` to include the new source
