"""
Neo4j database migration utility for the VulLink data pipeline.

This module provides the main entry point for the migration process,
handling command-line arguments and orchestrating the migration workflow.
"""

import sys
from migration.config import parse_args, get_db_config
from migration.migrator import Migrator


def main():
    """Main entry point for the migration script."""
    # Parse command-line arguments
    args = parse_args()
    
    # Get database configuration
    config = get_db_config(args)
    
    # Parse phases to run
    phases_arg = args.get("phases", ["all"])
    phases = set(phases_arg)
    
    # Get validation setting
    validate = not args.get("skip_validation", False)
    
    # Print migration parameters
    print(f"Starting migration with phases: {', '.join(phases)}")
    print(f"Database: {config.uri}")
    print(f"Data directory: {config.data_dir}")
    
    # Run migration
    migrator = Migrator(config)
    results = migrator.run_migration(phases, validate)
    
    # Check results
    if results.get("success", False):
        print("Migration completed successfully")
        
        # Print node counts
        if "node_counts" in results:
            node_counts = results["node_counts"]
            print("Node counts:")
            for node_type, count in node_counts.items():
                print(f"  {node_type}: {count}")
        
        # Print relationship counts
        if "relationship_counts" in results:
            rel_counts = results["relationship_counts"]
            print("Relationship counts:")
            for rel_type, count in rel_counts.items():
                print(f"  {rel_type}: {count}")
        
        sys.exit(0)
    else:
        print("Migration failed")
        if "error" in results:
            print(f"Error: {results['error']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
