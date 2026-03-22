"""
Database utility module for Neo4j interactions.

This module provides base functionality for connecting to and interacting with Neo4j.
"""

from neo4j import GraphDatabase
from neo4j.exceptions import ClientError, ServiceUnavailable

from migration.config import DBConfig


class Neo4jConnection:
    """Handles connection and basic operations with Neo4j database."""
    
    def __init__(self, config: DBConfig):
        """Initialize the Neo4j connection."""
        self.config = config
        self.driver = None
        self.connect()
    
    def connect(self):
        """Establish connection to the Neo4j database."""
        try:
            self.driver = GraphDatabase.driver(
                self.config.uri, 
                auth=(self.config.username, self.config.password)
            )
            # Test the connection
            with self.driver.session() as session:
                session.run("RETURN 1 AS test")
            print(f"Connected to Neo4j database at {self.config.uri}")
        except Exception as e:
            print(f"Failed to connect to Neo4j: {str(e)}")
            raise
    
    def close(self):
        """Close the database connection."""
        if self.driver:
            self.driver.close()
            self.driver = None
    
    def __del__(self):
        """Ensure connection is closed when object is destroyed."""
        self.close()
    
    def run_query(self, query, parameters=None):
        """Execute a Cypher query and return the results."""
        if parameters is None:
            parameters = {}
            
        if not self.driver:
            self.connect()
            
        with self.driver.session() as session:
            result = session.run(query, parameters)
            return [record.data() for record in result]
    
    def get_file_path(self, filename):
        """Get the full path to a data file."""
        import os
        return os.path.join(self.config.data_dir, filename)
    
    def run_transaction(self, work, parameters=None):
        """Run a transaction with the provided work function."""
        if parameters is None:
            parameters = {}
            
        if not self.driver:
            self.connect()
            
        with self.driver.session() as session:
            return session.write_transaction(work, parameters)
    
    def execute_safely(self, description, query, parameters=None):
        """Execute a query with error handling and logging."""
        try:
            print(f"Executing: {description}")
            result = self.run_query(query, parameters)
            print(f"Completed: {description}")
            return result
        except Exception as e:
            print(f"Error executing {description}: {e}")
            raise
    
    def assert_property_count(self, label, expected_count):
        """Assert that all nodes with the given label have the expected number of properties."""
        query = f"""
        MATCH (n:{label})
        WITH size(keys(n)) AS propCount, count(*) AS mismatchCount
        WHERE propCount <> $expected_count
        RETURN mismatchCount
        """
        result = self.run_query(query, {"expected_count": expected_count})
        mismatch = result[0]["mismatchCount"] if result else 0
        
        if mismatch > 0:
            msg = (f"Property constraint violation for {label}: "
                  f"{mismatch} node(s) do not have the expected {expected_count} properties.")
            print(msg)
            return False
        else:
            print(f"All {label} nodes have the expected {expected_count} properties.")
            return True
    
    def assert_relationship_property_count(self, rel_type, expected_count):
        """Assert that all relationships of the given type have the expected number of properties."""
        query = f"""
        MATCH ()-[r:{rel_type}]->()
        WITH size(keys(r)) AS propCount, count(*) AS mismatchCount
        WHERE propCount <> $expected_count
        RETURN mismatchCount
        """
        result = self.run_query(query, {"expected_count": expected_count})
        mismatch = result[0]["mismatchCount"] if result else 0
        
        if mismatch > 0:
            msg = (f"Property constraint violation for relationships of type {rel_type}: "
                  f"{mismatch} relationship(s) do not have the expected {expected_count} properties.")
            print(msg)
            return False
        else:
            print(f"All relationships of type {rel_type} have the expected {expected_count} properties.")
            return True 