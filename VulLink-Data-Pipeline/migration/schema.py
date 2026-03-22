"""
Schema operations module for Neo4j database.

This module handles database schema operations such as creating constraints and indexes.
"""

import logging
from typing import List

from neo4j.exceptions import ClientError

from migration.db import Neo4jConnection

logger = logging.getLogger("migration.schema")


class SchemaManager:
    """Manages database schema operations like constraints and indexes."""
    
    def __init__(self, db_conn: Neo4jConnection):
        """
        Initialize the schema manager.
        
        Args:
            db_conn: Database connection
        """
        self.db = db_conn
    
    def create_constraints(self) -> bool:
        """
        Create uniqueness constraints for all node types.
        
        Returns:
            True if all constraints were created successfully, False otherwise
        """
        constraints = [
            "CREATE CONSTRAINT UniqueCveID IF NOT EXISTS ON (v:Vulnerability) ASSERT v.cveID IS UNIQUE",
            "CREATE CONSTRAINT UniqueEID IF NOT EXISTS ON (e:Exploit) ASSERT e.eid IS UNIQUE",
            "CREATE CONSTRAINT UniqueAuthorName IF NOT EXISTS ON (a:Author) ASSERT a.authorName IS UNIQUE",
            "CREATE CONSTRAINT UniquecweID IF NOT EXISTS ON (w:Weakness) ASSERT w.cweID IS UNIQUE",
            "CREATE CONSTRAINT UniqueDomainName IF NOT EXISTS ON (d:Domain) ASSERT d.domainName IS UNIQUE",
            "CREATE CONSTRAINT UniqueProductName IF NOT EXISTS ON (p:Product) ASSERT p.productName IS UNIQUE",
            "CREATE CONSTRAINT UniqueVendorName IF NOT EXISTS ON (v:Vendor) ASSERT v.vendorName IS UNIQUE"
        ]
        
        success = True
        
        for cons in constraints:
            try:
                self.db.run_query(cons)
                logger.info(f"Created constraint: {cons}")
            except ClientError as e:
                # Handle case where constraint already exists
                if "already exists" in str(e):
                    logger.info(f"Constraint already exists: {cons}")
                else:
                    logger.warning(f"Error creating constraint: {cons}, Error: {e}")
                    success = False
        
        return success
    
    def create_indexes(self) -> bool:
        """
        Create indexes for better query performance.
        
        Returns:
            True if all indexes were created successfully, False otherwise
        """
        index_queries = [
            "CREATE INDEX VulnerabilityV2version IF NOT EXISTS FOR (v:Vulnerability) ON (v.v2version)",
            "CREATE INDEX VulnerabilityV3version IF NOT EXISTS FOR (v:Vulnerability) ON (v.v3version)",
            "CREATE INDEX VulnerabilityPublishedDate IF NOT EXISTS FOR (v:Vulnerability) ON (v.publishedDate)",
            "CREATE INDEX VulnerabilityDescription IF NOT EXISTS FOR (v:Vulnerability) ON (v.description)",
            "CREATE INDEX ExploitExploitPublishDate IF NOT EXISTS FOR (e:Exploit) ON (e.exploitPublishDate)",
            """CREATE FULLTEXT INDEX VulnerabilityDescriptionFullTextSchema IF NOT EXISTS
               FOR (v:Vulnerability)
               ON EACH [v.description]"""
        ]
        
        success = True
        
        for query in index_queries:
            try:
                self.db.run_query(query)
                logger.info(f"Created index: {query}")
            except ClientError as e:
                # Handle case where index already exists
                if "already exists" in str(e):
                    logger.info(f"Index already exists: {query}")
                else:
                    logger.warning(f"Error creating index: {query}, Error: {e}")
                    success = False
        
        return success
    
    def get_constraint_list(self) -> List[str]:
        """
        Get a list of existing constraints in the database.
        
        Returns:
            List of constraint names
        """
        query = "SHOW CONSTRAINTS"
        try:
            result = self.db.run_query(query)
            return [record.get("name") for record in result if "name" in record]
        except Exception as e:
            logger.error(f"Error retrieving constraints: {e}")
            return []
    
    def get_index_list(self) -> List[str]:
        """
        Get a list of existing indexes in the database.
        
        Returns:
            List of index names
        """
        query = "SHOW INDEXES"
        try:
            result = self.db.run_query(query)
            return [record.get("name") for record in result if "name" in record]
        except Exception as e:
            logger.error(f"Error retrieving indexes: {e}")
            return []
    
    def drop_constraint(self, name: str) -> bool:
        """
        Drop a constraint by name.
        
        Args:
            name: Name of the constraint to drop
            
        Returns:
            True if the constraint was dropped successfully, False otherwise
        """
        query = f"DROP CONSTRAINT {name}"
        try:
            self.db.run_query(query)
            logger.info(f"Dropped constraint: {name}")
            return True
        except Exception as e:
            logger.error(f"Error dropping constraint {name}: {e}")
            return False
    
    def drop_index(self, name: str) -> bool:
        """
        Drop an index by name.
        
        Args:
            name: Name of the index to drop
            
        Returns:
            True if the index was dropped successfully, False otherwise
        """
        query = f"DROP INDEX {name}"
        try:
            self.db.run_query(query)
            logger.info(f"Dropped index: {name}")
            return True
        except Exception as e:
            logger.error(f"Error dropping index {name}: {e}")
            return False
    
    def reset_schema(self) -> bool:
        """
        Reset the database schema by dropping all constraints and indexes.
        
        Returns:
            True if the schema was reset successfully, False otherwise
        """
        success = True
        
        # Drop constraints
        for constraint in self.get_constraint_list():
            if not self.drop_constraint(constraint):
                success = False
        
        # Drop indexes
        for index in self.get_index_list():
            if not self.drop_index(index):
                success = False
        
        return success 