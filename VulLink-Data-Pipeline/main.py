import neo4j
from database_schema import CONSTRAINTS, INDEXES
from edb_pipeline import EDBPipeline
from nvd_pipeline import NVDPipeline

def create_constraints_and_indexes(driver):
    """
    Create constraints and indexes for the Neo4j database.
    """
    with driver.session() as session:
        print("Creating constraints...")    
        for constraint in CONSTRAINTS:
            session.run(CONSTRAINTS[constraint])
        print("Creating indexes...")
        for index in INDEXES:
            session.run(INDEXES[index])
            
        # Verify that constraints and indexes are created
        for constraint in CONSTRAINTS:
            result = session.run(f"CALL db.constraints() YIELD name WHERE name = '{constraint}' RETURN name")
            assert result.single() is not None, f"Constraint {constraint} was not created successfully."
        for index in INDEXES:
            result = session.run(f"CALL db.indexes() YIELD name WHERE name = '{index}' RETURN name")
            assert result.single() is not None, f"Index {index} was not created successfully."
        print("Constraints and indexes created successfully.")


def main():
    """
    Main function to orchestrate the migration process.
    """
    # Create Neo4j driver
    driver = neo4j.GraphDatabase.driver(
        "bolt://localhost:7687",
        auth=("neo4j", "Vanly180705!")
    )
    
    try:
        create_constraints_and_indexes(driver)
        
        # Begin the data pipeline process
        # Start with the NVD data pipeline
        nvd_pipeline = NVDPipeline(driver)
        try:
            nvd_success = nvd_pipeline.run()
        except Exception as e:
            print(f"NVD data pipeline failed with error: {e}")
            nvd_success = False
        if nvd_success:
            print("NVD data pipeline completed successfully.")
        else:
            print("NVD data pipeline failed.")
        edb_pipeline = EDBPipeline(driver)
        try:
            edb_success = edb_pipeline.run()
        except Exception as e:
            print(f"EBD data pipeline failed with error: {e}")
            edb_success = False
        if edb_success:
            print("EBD data pipeline completed successfully.")
        else:
            print("EBD data pipeline failed.")
            
    finally:
        driver.close()
    
if __name__ == "__main__":
    main()
