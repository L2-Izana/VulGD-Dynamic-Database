"""
Relationship operations module for Neo4j database.

This module handles relationship creation and validation operations.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple

from migration.db import Neo4jConnection

logger = logging.getLogger("migration.relationships")


class RelationshipManager:
    """Manages relationship operations like creation and validation."""
    
    def __init__(self, db_conn: Neo4jConnection):
        """
        Initialize the relationship manager.
        
        Args:
            db_conn: Database connection
        """
        self.db = db_conn
    
    def create_example_of_relationships(self, validate: bool = True) -> bool:
        """
        Create EXAMPLE_OF relationships between Vulnerability and Weakness nodes.
        
        Args:
            validate: Whether to validate relationships after creation
            
        Returns:
            True if creation was successful, False otherwise
        """
        file_path = self.db.get_file_path("VulnerabilityNodesAddProperties.csv")
        query = f"""
        CALL apoc.periodic.iterate(
          "CALL apoc.load.csv('{file_path}') YIELD map AS row RETURN row",
          "WITH row.cveID AS cveID, row.CWEID AS cweID
           WHERE cveID IS NOT NULL AND cweID IS NOT NULL
           MATCH (v:Vulnerability {{cveID:cveID}})
           MATCH (w:Weakness {{cweID:cweID}})
           MERGE (v)-[:EXAMPLE_OF]->(w)
           RETURN *",
          {{batchSize:500}})
        """
        
        try:
            self.db.execute_safely("Creating EXAMPLE_OF relationships", query)
            
            if validate:
                # Check if relationships were created
                count_query = "MATCH ()-[r:EXAMPLE_OF]->() RETURN count(r) AS count"
                result = self.db.run_query(count_query)
                count = result[0]["count"] if result else 0
                
                if count == 0:
                    logger.warning("No EXAMPLE_OF relationships were created")
                    return False
                
                logger.info(f"Created {count} EXAMPLE_OF relationships")
                return True
            
            return True
        except Exception as e:
            logger.error(f"Failed to create EXAMPLE_OF relationships: {e}")
            return False
    
    def create_domain_nodes_and_relationships(self, validate: bool = True) -> bool:
        """
        Create Domain nodes and REFERS_TO relationships.
        
        Args:
            validate: Whether to validate nodes and relationships after creation
            
        Returns:
            True if creation was successful, False otherwise
        """
        file_path = self.db.get_file_path("DomainNodes_Vulnerability_HAS_REFERENCE_Domain_relationship.csv")
        query = f"""
        CALL apoc.periodic.iterate(
          "CALL apoc.load.csv('{file_path}') YIELD map AS row RETURN row",
          "WITH row.cveID AS cveID, row.domainName AS domainName
           WHERE cveID IS NOT NULL AND domainName IS NOT NULL
           MERGE (d:Domain {{domainName:domainName}})
           WITH *
           MATCH (v:Vulnerability {{cveID:cveID}})
           MERGE (v)-[:REFERS_TO]->(d)
           RETURN *",
          {{batchSize:500}})
        """
        
        try:
            self.db.execute_safely("Creating Domain nodes and REFERS_TO relationships", query)
            
            if validate:
                # Validate Domain nodes
                domain_validation = self.db.assert_property_count("Domain", expected_count=1)
                
                # Check if relationships were created
                count_query = "MATCH ()-[r:REFERS_TO]->() RETURN count(r) AS count"
                result = self.db.run_query(count_query)
                count = result[0]["count"] if result else 0
                
                if count == 0:
                    logger.warning("No REFERS_TO relationships were created")
                    return False
                
                logger.info(f"Created {count} REFERS_TO relationships")
                return domain_validation
            
            return True
        except Exception as e:
            logger.error(f"Failed to create Domain nodes and REFERS_TO relationships: {e}")
            return False
    
    def create_product_nodes_and_relationships(self, validate: bool = True) -> bool:
        """
        Create Product nodes and AFFECTS relationships.
        
        Args:
            validate: Whether to validate nodes and relationships after creation
            
        Returns:
            True if creation was successful, False otherwise
        """
        file_path = self.db.get_file_path("ProductNodes_VendorNodes_Vulnerability_AFFECTS_Product_BELONGS_TO_Vendor.csv")
        query = f"""
        CALL apoc.periodic.iterate(
          "CALL apoc.load.csv('{file_path}') YIELD map AS row RETURN row",
          "WITH row.cveID AS cveID, row.Product AS productName, row.ProductType AS productType, toInteger(row.Nversions) AS numOfVersion
           WHERE cveID IS NOT NULL AND productName IS NOT NULL
           MERGE (p:Product {{productName:productName}})
             ON CREATE SET p.productType = productType
           WITH *
           MATCH (v:Vulnerability {{cveID:cveID}})
           MERGE (v)-[r:AFFECTS]->(p)
             ON CREATE SET r.numOfVersion = numOfVersion
           RETURN *",
          {{batchSize:500}})
        """
        
        try:
            self.db.execute_safely("Creating Product nodes and AFFECTS relationships", query)
            
            if validate:
                # Validate Product nodes
                product_validation = self.db.assert_property_count("Product", expected_count=2)
                
                # Check if relationships were created
                count_query = "MATCH ()-[r:AFFECTS]->() RETURN count(r) AS count"
                result = self.db.run_query(count_query)
                count = result[0]["count"] if result else 0
                
                if count == 0:
                    logger.warning("No AFFECTS relationships were created")
                    return False
                
                logger.info(f"Created {count} AFFECTS relationships")
                return product_validation
            
            return True
        except Exception as e:
            logger.error(f"Failed to create Product nodes and AFFECTS relationships: {e}")
            return False
    
    def create_vendor_nodes_and_relationships(self, validate: bool = True) -> bool:
        """
        Create Vendor nodes and BELONGS_TO relationships.
        
        Args:
            validate: Whether to validate nodes and relationships after creation
            
        Returns:
            True if creation was successful, False otherwise
        """
        file_path = self.db.get_file_path("ProductNodes_VendorNodes_Vulnerability_AFFECTS_Product_BELONGS_TO_Vendor.csv")
        query = f"""
        CALL apoc.periodic.iterate(
          "CALL apoc.load.csv('{file_path}') YIELD map AS row RETURN row",
          "WITH row.Product AS productName, row.Vendor AS vendorName
           WHERE productName IS NOT NULL AND vendorName IS NOT NULL
           MERGE (v:Vendor {{vendorName:vendorName}})
           WITH *
           MATCH (p:Product {{productName:productName}})
           MERGE (p)-[:BELONGS_TO]->(v)
           RETURN *",
          {{batchSize:500}})
        """
        
        try:
            self.db.execute_safely("Creating Vendor nodes and BELONGS_TO relationships", query)
            
            if validate:
                # Validate Vendor nodes
                vendor_validation = self.db.assert_property_count("Vendor", expected_count=1)
                
                # Check if relationships were created
                count_query = "MATCH ()-[r:BELONGS_TO]->() RETURN count(r) AS count"
                result = self.db.run_query(count_query)
                count = result[0]["count"] if result else 0
                
                if count == 0:
                    logger.warning("No BELONGS_TO relationships were created")
                    return False
                
                logger.info(f"Created {count} BELONGS_TO relationships")
                return vendor_validation
            
            return True
        except Exception as e:
            logger.error(f"Failed to create Vendor nodes and BELONGS_TO relationships: {e}")
            return False
    
    def create_exploits_relationships(self, validate: bool = True) -> bool:
        """
        Create EXPLOITS relationships between Exploit and Vulnerability nodes.
        
        Args:
            validate: Whether to validate relationships after creation
            
        Returns:
            True if creation was successful, False otherwise
        """
        file_path = self.db.get_file_path("Vulnerability_EXPLOITED_Exploit_relationship.csv")
        query = f"""
        CALL apoc.periodic.iterate(
          "CALL apoc.load.csv('{file_path}') YIELD map AS row RETURN row",
          "WITH row.cveID AS cveID, row.ExploitID AS eid
           WHERE cveID IS NOT NULL AND eid IS NOT NULL
           MATCH (v:Vulnerability {{cveID:cveID}})
           MATCH (e:Exploit {{eid:eid}})
           MERGE (e)-[:EXPLOITS]->(v)
           RETURN *",
          {{batchSize:500}})
        """
        
        try:
            self.db.execute_safely("Creating EXPLOITS relationships", query)
            
            if validate:
                # Check if relationships were created
                count_query = "MATCH ()-[r:EXPLOITS]->() RETURN count(r) AS count"
                result = self.db.run_query(count_query)
                count = result[0]["count"] if result else 0
                
                if count == 0:
                    logger.warning("No EXPLOITS relationships were created")
                    return False
                
                logger.info(f"Created {count} EXPLOITS relationships")
                return True
            
            return True
        except Exception as e:
            logger.error(f"Failed to create EXPLOITS relationships: {e}")
            return False
    
    def create_writes_relationships(self, validate: bool = True) -> bool:
        """
        Create WRITES relationships between Author and Exploit nodes.
        
        Args:
            validate: Whether to validate relationships after creation
            
        Returns:
            True if creation was successful, False otherwise
        """
        query = """
        MATCH (e:Exploit), (a:Author)
        WHERE e.author = a.authorName
        MERGE (a)-[:WRITES]->(e)
        RETURN count(*) AS count
        """
        
        try:
            result = self.db.execute_safely("Creating WRITES relationships", query)
            count = result[0]["count"] if result else 0
            
            if count == 0 and validate:
                logger.warning("No WRITES relationships were created")
                return False
            
            logger.info(f"Created {count} WRITES relationships")
            return True
        except Exception as e:
            logger.error(f"Failed to create WRITES relationships: {e}")
            return False
    
    def update_affects_relationships(self, validate: bool = True) -> bool:
        """
        Update AFFECTS relationships with affectedVersion property.
        
        Args:
            validate: Whether to validate relationships after update
            
        Returns:
            True if update was successful, False otherwise
        """
        # Initialize affectedVersion to an empty list for all AFFECTS relationships
        init_query = """
        MATCH ()-[r:AFFECTS]->()
        SET r.affectedVersion = []
        RETURN count(r) AS affectedCount
        """
        
        try:
            init_result = self.db.execute_safely("Initializing affectedVersion property", init_query)
            init_count = init_result[0]["affectedCount"] if init_result else 0
            logger.info(f"Initialized affectedVersion for {init_count} AFFECTS relationships")
            
            # Update the affectedVersion property based on CSV input
            file_path = self.db.get_file_path("AffectsAddProperty.csv")
            update_query = f"""
            CALL apoc.periodic.iterate(
              "CALL apoc.load.csv('{file_path}') YIELD map AS row RETURN row",
              "WITH row.cveID AS cveID, row.Product AS productName, row.Version AS version
               WHERE cveID IS NOT NULL AND productName IS NOT NULL AND version IS NOT NULL
               MATCH (v:Vulnerability {{cveID:cveID}})-[r:AFFECTS]->(p:Product {{productName:productName}})
               SET r.affectedVersion = r.affectedVersion + [version]
               RETURN count(*)",
              {{batchSize:500}})
            """
            
            self.db.execute_safely("Updating AFFECTS relationships with affectedVersion", update_query)
            
            if validate:
                return self.db.assert_relationship_property_count("AFFECTS", expected_count=2)
            
            return True
        except Exception as e:
            logger.error(f"Failed to update AFFECTS relationships: {e}")
            return False
    
    def count_relationships(self) -> Dict[str, int]:
        """
        Count the number of relationships of each type.
        
        Returns:
            Dictionary with relationship type as key and count as value
        """
        counts = {}
        rel_types = ["EXPLOITS", "AFFECTS", "BELONGS_TO", "EXAMPLE_OF", "WRITES", "REFERS_TO"]
        
        for rel_type in rel_types:
            query = f"MATCH ()-[r:{rel_type}]->() RETURN count(r) AS count"
            try:
                result = self.db.run_query(query)
                counts[rel_type] = result[0]["count"] if result else 0
            except Exception as e:
                logger.error(f"Error counting {rel_type} relationships: {e}")
                counts[rel_type] = -1
        
        return counts
    
    def create_all_relationships(self, validate: bool = True) -> Dict[str, bool]:
        """
        Create all relationship types.
        
        Args:
            validate: Whether to validate relationships after creation
            
        Returns:
            Dictionary with creation results for each relationship type
        """
        results = {}
        
        # Create relationships in dependency order
        results["ExampleOf"] = self.create_example_of_relationships(validate)
        results["Domain"] = self.create_domain_nodes_and_relationships(validate)
        results["Product"] = self.create_product_nodes_and_relationships(validate)
        results["Vendor"] = self.create_vendor_nodes_and_relationships(validate)
        results["Exploits"] = self.create_exploits_relationships(validate)
        results["Writes"] = self.create_writes_relationships(validate)
        
        # Update relationship properties
        if results.get("Product", False):
            results["AffectsUpdate"] = self.update_affects_relationships(validate)
        
        return results 