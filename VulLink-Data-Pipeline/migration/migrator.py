"""
Main migration coordinator module.

This module coordinates the entire migration process using the various components.
"""

import time
from migration.config import DBConfig
from migration.db import Neo4jConnection
from migration.operations import OperationsManager


class Migrator:
    """Main migration coordinator class."""
    
    def __init__(self, config):
        """Initialize the migrator."""
        self.config = config
        self.db = Neo4jConnection(config)
        self.operations = OperationsManager(self.db)
    
    def run_migration(self, phases=None, validate=True):
        """
        Run the migration process.
        
        Args:
            phases: Set of phases to run ('schema', 'nodes', 'relationships', 'cleanup', 'all')
            validate: Whether to validate data during migration
            
        Returns:
            Dictionary with migration results
        """
        if phases is None:
            phases = {"all"}
        
        run_all = "all" in phases
        results = {}
        start_time = time.time()
        
        try:
            # Verify prerequisites
            if not self.operations.check_prerequisites():
                print("Prerequisites check failed. Aborting migration.")
                results["success"] = False
                results["error"] = "Prerequisites check failed"
                return results
            
            # Run schema phase
            if run_all or "schema" in phases:
                schema_success = self.operations.create_constraints() and self.operations.create_indexes()
                results["schema"] = {"success": schema_success}
                
                if not schema_success and "schema" in phases:
                    print("Schema phase failed. Aborting migration.")
                    results["success"] = False
                    return results
            
            # Run nodes phase
            if run_all or "nodes" in phases:
                nodes_success = self.operations.migrate_all_nodes(validate)
                results["nodes"] = {"success": nodes_success}
                
                if not nodes_success and "nodes" in phases:
                    print("Nodes phase failed. Aborting migration.")
                    results["success"] = False
                    return results
            
            # Run relationships phase
            if run_all or "relationships" in phases:
                rel_success = self.operations.create_all_relationships(validate)
                results["relationships"] = {"success": rel_success}
                
                if not rel_success and "relationships" in phases:
                    print("Relationships phase failed. Aborting migration.")
                    results["success"] = False
                    return results
            
            # Get statistics
            results["node_counts"] = self.operations.count_nodes()
            results["relationship_counts"] = self.operations.count_relationships()
            
            # Set overall success flag
            results["success"] = True
            duration = time.time() - start_time
            print(f"Migration completed in {duration:.2f} seconds")
            
            return results
            
        except Exception as e:
            print(f"Unexpected error during migration: {e}")
            results["success"] = False
            results["error"] = str(e)
            return results
        finally:
            # Close database connection
            self.db.close() 