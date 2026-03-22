"""
Configuration module for the Neo4j migration utility.
"""

import os
import json
import argparse
from dataclasses import dataclass


@dataclass
class DBConfig:
    """Database connection configuration."""
    uri: str
    username: str
    password: str
    data_dir: str = "data"
    
    @classmethod
    def from_dict(cls, config_dict):
        """Create a DBConfig from a dictionary."""
        return cls(
            uri=config_dict.get("uri", "bolt://localhost:7687"),
            username=config_dict.get("username", "neo4j"),
            password=config_dict.get("password", "neo4j"),
            data_dir=config_dict.get("data_dir", "data")
        )


def load_config_from_file(file_path):
    """Load configuration from a JSON file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        raise ValueError(f"Failed to load configuration from {file_path}: {str(e)}")


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Migrate vulnerability data to Neo4j database")
    
    parser.add_argument("--config", type=str, help="Path to configuration file")
    parser.add_argument("--uri", type=str, default="bolt://localhost:7687", help="Neo4j database URI")
    parser.add_argument("--username", type=str, default="neo4j", help="Neo4j database username")
    parser.add_argument("--password", type=str, default="neo4j", help="Neo4j database password")
    parser.add_argument("--data-dir", type=str, default="data", help="Directory containing data files")
    parser.add_argument("--phases", type=str, nargs="+", 
                       choices=["schema", "nodes", "relationships", "cleanup", "all"],
                       default=["all"], help="Migration phases to run")
    parser.add_argument("--skip-validation", action="store_true", help="Skip validation steps")
    
    args = parser.parse_args()
    return vars(args)


def get_db_config(args):
    """Create a DBConfig object from command-line arguments or config file."""
    # If config file is provided, load from file
    if args.get("config"):
        config_dict = load_config_from_file(args["config"])
        db_config = DBConfig.from_dict(config_dict.get("database", {}))
    else:
        # Otherwise use command-line arguments
        db_config = DBConfig(
            uri=args.get("uri", "bolt://localhost:7687"),
            username=args.get("username", "neo4j"),
            password=args.get("password", "neo4j"),
            data_dir=args.get("data_dir", "data")
        )
    
    return db_config 