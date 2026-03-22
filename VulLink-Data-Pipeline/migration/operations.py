"""
Database operations module for Neo4j database.

This module handles schema, node, and relationship operations.
"""

import os
from migration.db import Neo4jConnection


class OperationsManager:
    """Manages database operations for schema, nodes, and relationships."""
    
    def __init__(self, db_conn):
        """Initialize the operations manager."""
        self.db = db_conn
        
        # List of required data files
        self.required_files = [
            "VulnerabilityNodes.csv",
            "ExploitNodes.csv",
            "WeaknessNodes.csv",
            "VulnerabilityNodesAddProperties.csv",
            "DomainNodes_Vulnerability_HAS_REFERENCE_Domain_relationship.csv",
            "ProductNodes_VendorNodes_Vulnerability_AFFECTS_Product_BELONGS_TO_Vendor.csv",
            "AffectsAddProperty.csv"
        ]
    
    def check_prerequisites(self):
        """Check if required files exist and database is accessible."""
        # Check if required files exist
        missing_files = []
        for filename in self.required_files:
            file_path = self.db.get_file_path(filename)
            if not os.path.isfile(file_path):
                missing_files.append(filename)
        
        if missing_files:
            print(f"Missing required files: {', '.join(missing_files)}")
            return False
        
        # Test database connection
        try:
            self.db.run_query("RETURN 1 AS test")
            print("Database connection successful")
            return True
        except Exception as e:
            print(f"Failed to connect to database: {e}")
            return False
    
    # Schema operations
    def create_constraints(self):
        """Create uniqueness constraints for all node types."""
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
                print(f"Created constraint: {cons}")
            except Exception as e:
                if "already exists" in str(e):
                    print(f"Constraint already exists: {cons}")
                else:
                    print(f"Error creating constraint: {cons}, Error: {e}")
                    success = False
        
        return success
    
    def create_indexes(self):
        """Create indexes for better query performance."""
        index_queries = [
            "CREATE INDEX VulnerabilityV2version IF NOT EXISTS FOR (v:Vulnerability) ON (v.v2version)",
            "CREATE INDEX VulnerabilityPublishedDate IF NOT EXISTS FOR (v:Vulnerability) ON (v.publishedDate)",
            "CREATE FULLTEXT INDEX VulnerabilityDescriptionFullTextSchema IF NOT EXISTS FOR (v:Vulnerability) ON EACH [v.description]"
        ]
        
        success = True
        for query in index_queries:
            try:
                self.db.run_query(query)
                print(f"Created index: {query}")
            except Exception as e:
                if "already exists" in str(e):
                    print(f"Index already exists: {query}")
                else:
                    print(f"Error creating index: {query}, Error: {e}")
                    success = False
        
        return success
    
    # Node operations
    def migrate_vulnerability_nodes(self, validate=True):
        """Migrate vulnerability nodes from CSV file."""
        file_path = self.db.get_file_path("VulnerabilityNodes.csv")
        query = f"""
        LOAD CSV WITH HEADERS FROM 'file:///{file_path}' AS row
        WITH
           row.cveID as cveID,
           date(row.publishedDate) AS publishedDate,
           row.description_value AS description,
           toInteger(row.num_reference) AS numOfReference,
           toInteger(row.v2version) AS v2version,
           toFloat(row.v2baseScore) AS v2baseScore,
           row.v2vectorString AS v2vectorString,
           row.v3vectorString AS v3vectorString,
           toInteger(row.v3baseScore) AS v3baseScore
        MERGE (v:Vulnerability {cveID:cveID})
           ON CREATE SET
             v.publishedDate = publishedDate,
             v.description = description,
             v.numOfReference = numOfReference,
             v.v2version = v2version,
             v.v2baseScore = v2baseScore,
             v.v2vectorString = v2vectorString,
             v.v3vectorString = v3vectorString,
             v.v3baseScore = v3baseScore
        RETURN count(*)
        """
        
        try:
            self.db.run_query(query)
            print("Migrated Vulnerability nodes")
            return True
        except Exception as e:
            print(f"Failed to migrate Vulnerability nodes: {e}")
            return False
    
    def migrate_exploit_nodes(self, validate=True):
        """Migrate exploit nodes from CSV file."""
        file_path = self.db.get_file_path("ExploitNodes.csv")
        query = f"""
        LOAD CSV WITH HEADERS FROM 'file:///{file_path}' AS row
        WITH
           row.ExploitID AS eid,
           date(row.Exploit_Date) AS exploitPublishDate,
           row.Author AS author,
           row.Exploit_Type AS exploitType,
           row.Platform AS platform
        MERGE (e:Exploit {{eid:eid}})
           ON CREATE SET
             e.exploitPublishDate = exploitPublishDate,
             e.exploitType = exploitType,
             e.platform = platform
        RETURN count(*)
        """
        
        try:
            self.db.run_query(query)
            print("Migrated Exploit nodes")
            return True
        except Exception as e:
            print(f"Failed to migrate Exploit nodes: {e}")
            return False
    
    def migrate_weakness_nodes(self, validate=True):
        """Migrate weakness nodes from CSV file."""
        file_path = self.db.get_file_path("WeaknessNodes.csv")
        query = f"""
        LOAD CSV WITH HEADERS FROM 'file:///{file_path}' AS row
        WITH
           row.cweID AS cweID,
           row.cweName AS cweName,
           row.description AS description
        MERGE (w:Weakness {{cweID:cweID}})
           ON CREATE SET
             w.cweName = cweName,
             w.description = description
        RETURN count(*)
        """
        
        try:
            self.db.run_query(query)
            print("Migrated Weakness nodes")
            return True
        except Exception as e:
            print(f"Failed to migrate Weakness nodes: {e}")
            return False
    
    # Relationship operations
    def create_example_of_relationships(self, validate=True):
        """Create EXAMPLE_OF relationships between Vulnerability and Weakness nodes."""
        file_path = self.db.get_file_path("VulnerabilityNodesAddProperties.csv")
        query = f"""
        LOAD CSV WITH HEADERS FROM 'file:///{file_path}' AS row
        WITH row.cveID AS cveID, row.CWEID AS cweID
        WHERE cveID IS NOT NULL AND cweID IS NOT NULL
        MATCH (v:Vulnerability {{cveID:cveID}})
        MATCH (w:Weakness {{cweID:cweID}})
        MERGE (v)-[:EXAMPLE_OF]->(w)
        RETURN count(*)
        """
        
        try:
            self.db.run_query(query)
            print("Created EXAMPLE_OF relationships")
            return True
        except Exception as e:
            print(f"Failed to create EXAMPLE_OF relationships: {e}")
            return False
    
    def create_exploits_relationships(self, validate=True):
        """Create EXPLOITS relationships between Exploit and Vulnerability nodes."""
        file_path = self.db.get_file_path("Vulnerability_EXPLOITED_Exploit_relationship.csv")
        query = f"""
        LOAD CSV WITH HEADERS FROM 'file:///{file_path}' AS row
        WITH row.cveID AS cveID, row.ExploitID AS eid
        WHERE cveID IS NOT NULL AND eid IS NOT NULL
        MATCH (v:Vulnerability {{cveID:cveID}})
        MATCH (e:Exploit {{eid:eid}})
        MERGE (e)-[:EXPLOITS]->(v)
        RETURN count(*)
        """
        
        try:
            self.db.run_query(query)
            print("Created EXPLOITS relationships")
            return True
        except Exception as e:
            print(f"Failed to create EXPLOITS relationships: {e}")
            return False
    
    # Combined operations
    def migrate_all_nodes(self, validate=True):
        """Migrate all node types."""
        results = {}
        
        # Core node types
        results["Vulnerability"] = self.migrate_vulnerability_nodes(validate)
        results["Exploit"] = self.migrate_exploit_nodes(validate)
        results["Weakness"] = self.migrate_weakness_nodes(validate)
        
        return all(results.values())
    
    def create_all_relationships(self, validate=True):
        """Create all relationship types."""
        results = {}
        
        # Create relationships
        results["ExampleOf"] = self.create_example_of_relationships(validate)
        results["Exploits"] = self.create_exploits_relationships(validate)
        
        return all(results.values())
    
    def count_nodes(self):
        """Count the number of nodes of each type."""
        counts = {}
        node_types = ["Vulnerability", "Exploit", "Weakness"]
        
        for node_type in node_types:
            query = f"MATCH (n:{node_type}) RETURN count(n) AS count"
            try:
                result = self.db.run_query(query)
                counts[node_type] = result[0]["count"] if result else 0
            except Exception as e:
                counts[node_type] = -1
        
        return counts
    
    def count_relationships(self):
        """Count the number of relationships of each type."""
        counts = {}
        rel_types = ["EXPLOITS", "EXAMPLE_OF"]
        
        for rel_type in rel_types:
            query = f"MATCH ()-[r:{rel_type}]->() RETURN count(r) AS count"
            try:
                result = self.db.run_query(query)
                counts[rel_type] = result[0]["count"] if result else 0
            except Exception as e:
                counts[rel_type] = -1
        
        return counts 