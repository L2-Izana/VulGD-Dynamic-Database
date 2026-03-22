"""
Node operations module for Neo4j database.

This module handles node migration and validation operations.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple

from migration.db import Neo4jConnection

logger = logging.getLogger("migration.nodes")


class NodeManager:
    """Manages node operations like migration and validation."""
    
    def __init__(self, db_conn: Neo4jConnection):
        """
        Initialize the node manager.
        
        Args:
            db_conn: Database connection
        """
        self.db = db_conn
    
    def migrate_vulnerability_nodes(self, validate: bool = True) -> bool:
        """
        Migrate vulnerability nodes from CSV file.
        
        Args:
            validate: Whether to validate nodes after migration
            
        Returns:
            True if migration was successful, False otherwise
        """
        file_path = self.db.get_file_path("VulnerabilityNodes.csv")
        query = f"""
        CALL apoc.periodic.iterate(
          "CALL apoc.load.csv('{file_path}') YIELD map AS row RETURN row",
          "WITH
             row.cveID as cveID,
             date(row.publishedDate) AS publishedDate,
             row.description_value AS description,
             toInteger(row.num_reference) AS numOfReference,
             toInteger(row.v2version) AS v2version,
             toFloat(row.v2baseScore) AS v2baseScore,
             row.v2accessVector AS v2accessVector,
             row.v2accessComplexity AS v2accessComplexity,
             row.v2authentication AS v2authentication,
             row.v2confidentialityImpact AS v2confidentialityImpact,
             row.v2integrityImpact AS v2integrityImpact,
             row.v2availabilityImpact AS v2availabilityImpact,
             row.v2vectorString AS v2vectorString,
             toInteger(row.v2impactScore) AS v2impactScore,
             toInteger(row.v2exploitabilityScore) AS v2exploitabilityScore,
             toBoolean(row.v2userInteractionRequired) AS v2userInteractionRequired,
             row.v2severity AS v2severity,
             toBoolean(row.v2obtainUserPrivilege) AS v2obtainUserPrivilege,
             toBoolean(row.v2obtainAllPrivilege) AS v2obtainAllPrivilege,
             toBoolean(row.v2acInsufInfo) AS v2acInsufInfo,
             toBoolean(row.v2obtainOtherPrivilege) AS v2obtainOtherPrivilege,
             toFloat(row.v3version) AS v3version,
             toInteger(row.v3baseScore) AS v3baseScore,
             row.v3attackVector AS v3attackVector,
             row.v3attackComplexity AS v3attackComplexity,
             row.v3privilegesRequired AS v3privilegesRequired,
             row.v3userInteraction AS v3userInteraction,
             row.v3scope AS v3scope,
             row.v3confidentialityImpact AS v3confidentialityImpact,
             row.v3integrityImpact AS v3integrityImpact,
             row.v3availabilityImpact AS v3availabilityImpact,
             row.v3vectorString AS v3vectorString,
             toInteger(row.v3impactScore) AS v3impactScore,
             toInteger(row.v3exploitabilityScore) AS v3exploitabilityScore,
             row.v3baseSeverity AS v3baseSeverity
          MERGE (v:Vulnerability {{cveID:cveID}})
             ON CREATE SET
               v.publishedDate = publishedDate,
               v.description = description,
               v.numOfReference = numOfReference,
               v.v2version = v2version,
               v.v2baseScore = v2baseScore,
               v.v2accessVector = v2accessVector,
               v.v2accessComplexity = v2accessComplexity,
               v.v2authentication = v2authentication,
               v.v2confidentialityImpact = v2confidentialityImpact,
               v.v2integrityImpact = v2integrityImpact,
               v.v2availabilityImpact = v2availabilityImpact,
               v.v2vectorString = v2vectorString,
               v.v2impactScore = v2impactScore,
               v.v2exploitabilityScore = v2exploitabilityScore,
               v.v2userInteractionRequired = v2userInteractionRequired,
               v.v2severity = v2severity,
               v.v2obtainUserPrivilege = v2obtainUserPrivilege,
               v.v2obtainAllPrivilege = v2obtainAllPrivilege,
               v.v2acInsufInfo = v2acInsufInfo,
               v.v2obtainOtherPrivilege = v2obtainOtherPrivilege,
               v.v3version = v3version,
               v.v3baseScore = v3baseScore,
               v.v3attackVector = v3attackVector,
               v.v3attackComplexity = v3attackComplexity,
               v.v3privilegesRequired = v3privilegesRequired,
               v.v3userInteraction = v3userInteraction,
               v.v3scope = v3scope,
               v.v3confidentialityImpact = v3confidentialityImpact,
               v.v3integrityImpact = v3integrityImpact,
               v.v3availabilityImpact = v3availabilityImpact,
               v.v3vectorString = v3vectorString,
               v.v3impactScore = v3impactScore,
               v.v3exploitabilityScore = v3exploitabilityScore,
               v.v3baseSeverity = v3baseSeverity
          RETURN count(*)
        , {{batchSize:500}})
        """
        
        try:
            self.db.execute_safely("Migrating Vulnerability nodes", query)
            
            if validate:
                return self.db.assert_property_count("Vulnerability", expected_count=35)
            
            return True
        except Exception as e:
            logger.error(f"Failed to migrate Vulnerability nodes: {e}")
            return False
    
    def migrate_exploit_nodes(self, validate: bool = True) -> bool:
        """
        Migrate exploit nodes from CSV file.
        
        Args:
            validate: Whether to validate nodes after migration
            
        Returns:
            True if migration was successful, False otherwise
        """
        file_path = self.db.get_file_path("ExploitNodes.csv")
        query = f"""
        CALL apoc.periodic.iterate(
          "CALL apoc.load.csv('{file_path}') YIELD map AS row RETURN row",
          "WITH
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
          RETURN count(*)",
          {{batchSize:500}})
        """
        
        try:
            self.db.execute_safely("Migrating Exploit nodes", query)
            
            if validate:
                return self.db.assert_property_count("Exploit", expected_count=4)
            
            return True
        except Exception as e:
            logger.error(f"Failed to migrate Exploit nodes: {e}")
            return False
    
    def migrate_author_nodes(self, validate: bool = True) -> bool:
        """
        Migrate author nodes from CSV file.
        
        Args:
            validate: Whether to validate nodes after migration
            
        Returns:
            True if migration was successful, False otherwise
        """
        file_path = self.db.get_file_path("ExploitNodes.csv")
        query = f"""
        CALL apoc.periodic.iterate(
          "CALL apoc.load.csv('{file_path}') YIELD map AS row RETURN row",
          "WITH row.Author AS authorName
           WHERE authorName IS NOT NULL AND authorName <> ''
           MERGE (a:Author {{authorName: authorName}})
           ON CREATE SET a.authorName = authorName
           RETURN count(*)",
          {{batchSize:500}})
        """
        
        try:
            self.db.execute_safely("Migrating Author nodes", query)
            
            if validate:
                return self.db.assert_property_count("Author", expected_count=1)
            
            return True
        except Exception as e:
            logger.error(f"Failed to migrate Author nodes: {e}")
            return False
    
    def migrate_weakness_nodes(self, validate: bool = True) -> bool:
        """
        Migrate weakness nodes from CSV file.
        
        Args:
            validate: Whether to validate nodes after migration
            
        Returns:
            True if migration was successful, False otherwise
        """
        file_path = self.db.get_file_path("WeaknessNodes.csv")
        query = f"""
        CALL apoc.periodic.iterate(
          "CALL apoc.load.csv('{file_path}') YIELD map AS row RETURN row",
          "WITH
             row.cweID AS cweID,
             split(row.cweView,',') AS cweView,
             row.cweName AS cweName,
             row.weaknessAbstraction AS weaknessAbstraction,
             row.status AS status,
             row.description AS description,
             row.extendedDescription AS extendedDescription
          MERGE (w:Weakness {{cweID:cweID}})
             ON CREATE SET
               w.cweView = cweView,
               w.cweName = cweName,
               w.weaknessAbstraction = weaknessAbstraction,
               w.status = status,
               w.description = description,
               w.extendedDescription = extendedDescription
          RETURN count(*)",
          {{batchSize:500}})
        """
        
        try:
            self.db.execute_safely("Migrating Weakness nodes", query)
            
            if validate:
                return self.db.assert_property_count("Weakness", expected_count=7)
            
            return True
        except Exception as e:
            logger.error(f"Failed to migrate Weakness nodes: {e}")
            return False
    
    def update_vulnerability_nodes(self, validate: bool = True) -> bool:
        """
        Update Vulnerability nodes with additional properties.
        
        Args:
            validate: Whether to validate nodes after update
            
        Returns:
            True if update was successful, False otherwise
        """
        file_path = self.db.get_file_path("VulnerabilityNodesAddProperties.csv")
        query = f"""
        CALL apoc.periodic.iterate(
          "CALL apoc.load.csv('{file_path}') YIELD map AS row RETURN row",
          "WITH row.cveID AS cveID, row.GainedAccess AS gainedAccess, split(row.VulnerabilityType,',') as vulnerabilityType
           MATCH (v:Vulnerability {{cveID:cveID}})
           SET v.gainedAccess = gainedAccess, v.vulnerabilityType = vulnerabilityType
           RETURN count(*)",
          {{batchSize:500}})
        """
        
        try:
            self.db.execute_safely("Updating Vulnerability nodes with additional properties", query)
            
            if validate:
                # After update, Vulnerability nodes have 2 additional properties
                return self.db.assert_property_count("Vulnerability", expected_count=37)
            
            return True
        except Exception as e:
            logger.error(f"Failed to update Vulnerability nodes: {e}")
            return False
    
    def delete_reject_vulnerabilities(self) -> Tuple[bool, int]:
        """
        Delete Vulnerability nodes with description starting with '** REJECT **'.
        
        Returns:
            Tuple of (success boolean, count of deleted nodes)
        """
        query = """
        MATCH (n:Vulnerability)
        WHERE n.description STARTS WITH '** REJECT **'
        WITH n LIMIT 10000
        DETACH DELETE n
        RETURN count(n) AS deletedCount
        """
        
        try:
            result = self.db.execute_safely("Deleting rejected Vulnerability nodes", query)
            deleted_count = result[0]["deletedCount"] if result else 0
            logger.info(f"Deleted {deleted_count} rejected Vulnerability nodes")
            return True, deleted_count
        except Exception as e:
            logger.error(f"Failed to delete rejected Vulnerability nodes: {e}")
            return False, 0
    
    def initialize_exploit_properties(self) -> Tuple[bool, int]:
        """
        Initialize exploitability and exploitDate on Vulnerability nodes.
        
        Returns:
            Tuple of (success boolean, count of updated nodes)
        """
        # Initialize all nodes
        init_query = """
        MATCH (v:Vulnerability)
        SET v.exploitability = 0, v.exploitDate = []
        RETURN count(v) AS countVuln
        """
        
        try:
            init_result = self.db.execute_safely("Initializing exploit properties", init_query)
            init_count = init_result[0]["countVuln"] if init_result else 0
            logger.info(f"Initialized exploit properties for {init_count} Vulnerability nodes")
            
            # Update nodes with relationships
            update_query = """
            MATCH (v:Vulnerability)<-[r:EXPLOITS]-(e:Exploit)
            SET v.exploitability = 1, v.exploitDate = v.exploitDate + [e.exploitPublishDate]
            RETURN count(v) AS updatedCount
            """
            
            update_result = self.db.execute_safely("Updating exploit properties based on relationships", update_query)
            update_count = update_result[0]["updatedCount"] if update_result else 0
            logger.info(f"Updated exploit properties for {update_count} Vulnerability nodes")
            
            return True, update_count
        except Exception as e:
            logger.error(f"Failed to initialize exploit properties: {e}")
            return False, 0
    
    def count_nodes(self) -> Dict[str, int]:
        """
        Count the number of nodes of each type.
        
        Returns:
            Dictionary with node type as key and count as value
        """
        counts = {}
        node_types = ["Vulnerability", "Exploit", "Author", "Weakness", "Product", "Vendor", "Domain"]
        
        for node_type in node_types:
            query = f"MATCH (n:{node_type}) RETURN count(n) AS count"
            try:
                result = self.db.run_query(query)
                counts[node_type] = result[0]["count"] if result else 0
            except Exception as e:
                logger.error(f"Error counting {node_type} nodes: {e}")
                counts[node_type] = -1
        
        return counts
    
    def migrate_all_nodes(self, validate: bool = True) -> Dict[str, bool]:
        """
        Migrate all node types.
        
        Args:
            validate: Whether to validate nodes after migration
            
        Returns:
            Dictionary with migration results for each node type
        """
        results = {}
        
        # Core node types
        results["Vulnerability"] = self.migrate_vulnerability_nodes(validate)
        results["Exploit"] = self.migrate_exploit_nodes(validate)
        results["Author"] = self.migrate_author_nodes(validate)
        results["Weakness"] = self.migrate_weakness_nodes(validate)
        
        # Additional properties on Vulnerability nodes
        if results["Vulnerability"]:
            results["VulnerabilityUpdate"] = self.update_vulnerability_nodes(validate)
        
        return results 