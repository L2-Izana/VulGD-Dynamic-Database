# VulLink Neo4j Migration

A simplified migration utility for transferring vulnerability data to Neo4j.

## Structure

The migration code consists of:

- **config.py**: Basic configuration 
- **db.py**: Database connection
- **operations.py**: Schema, node and relationship operations
- **migrator.py**: Migration coordination
- **main.py**: Command-line entry point

## Requirements

- Neo4j Database (4.0+)
- Neo4j APOC plugin
- Python neo4j module

## Installation

```bash
pip install -e .
```

## Usage

### Command Line

```bash
# Run the full migration
python -m migration.main

# Run specific phases
python -m migration.main --phases schema nodes

# Configure database
python -m migration.main --uri bolt://localhost:7687 --username neo4j --password password

# Specify data directory
python -m migration.main --data-dir /path/to/data

# Skip validation
python -m migration.main --skip-validation
```

### API

```python
from migration import run_migration

# Quick run
results = run_migration(
    uri="bolt://localhost:7687",
    username="neo4j",
    password="password",
    data_dir="data",
    phases=["schema", "nodes", "relationships"],
    validate=True
)

# Using Migrator directly
from migration import Migrator, DBConfig

config = DBConfig(uri="bolt://localhost:7687", username="neo4j", password="password")
migrator = Migrator(config)
results = migrator.run_migration({"schema", "nodes", "relationships"})
```

## Migration Phases

The migration includes these phases:

1. **schema**: Create constraints and indexes
2. **nodes**: Create nodes (Vulnerability, Exploit, Weakness)
3. **relationships**: Create relationships between nodes

## Data Files

The migration requires CSV files in the data directory. Key files include:

- **VulnerabilityNodes.csv**: Core vulnerability data
- **ExploitNodes.csv**: Exploit data 
- **WeaknessNodes.csv**: Weakness data
- **VulnerabilityNodesAddProperties.csv**: Additional properties
- **Vulnerability_EXPLOITED_Exploit_relationship.csv**: Relationships 