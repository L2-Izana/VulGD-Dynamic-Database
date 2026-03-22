"""
VulLink migration package for Neo4j database.

This package provides utilities for migrating vulnerability data to a Neo4j graph database.
"""

__version__ = "1.0.0"

# Import main components
from migration.config import DBConfig
from migration.migrator import Migrator
from migration.operations import OperationsManager

# Convenience function for running migration
def run_migration(
    uri="bolt://localhost:7687",
    username="neo4j",
    password="neo4j",
    data_dir="data",
    phases=None,
    validate=True
):
    """
    Run migration as a function.
    
    Args:
        uri: Neo4j database URI
        username: Neo4j database username
        password: Neo4j database password
        data_dir: Directory containing data files
        phases: List of phases to run ('schema', 'nodes', 'relationships', 'all')
        validate: Whether to validate data during migration
        
    Returns:
        Dictionary with migration results
    """
    # Create configuration
    config = DBConfig(uri=uri, username=username, password=password, data_dir=data_dir)
    
    # Create migrator
    migrator = Migrator(config)
    
    # Run migration
    if phases is None:
        phases = ["all"]
    
    return migrator.run_migration(set(phases), validate) 