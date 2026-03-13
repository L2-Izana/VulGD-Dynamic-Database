from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Dict, List, Any, Optional
import re
from app.db.database import get_db, Neo4jDatabase
from neo4j.time import Date, DateTime

router = APIRouter()

# Regular expressions to detect data modification operations
WRITE_OPERATIONS = re.compile(
    r"\b(CREATE|DELETE|REMOVE|SET|MERGE|DROP|CALL|ADMIN|LOAD CSV)\b", 
    re.IGNORECASE
)

WRITE_PROCEDURES = re.compile(
    r"\bcall\s+db\.", 
    re.IGNORECASE
)

def neo4j_to_json(obj):
    """
    Recursively convert Neo4j objects to JSON-serializable data.
    Handles:
    - Node / Relationship → dict
    - neo4j.time.Date / DateTime → ISO string
    - lists and dicts recursively
    """
    if isinstance(obj, (Date, DateTime)):
        return obj.iso_format()
    elif hasattr(obj, "items"):  # Node or Relationship
        return {k: neo4j_to_json(v) for k, v in dict(obj).items()}
    elif isinstance(obj, list):
        return [neo4j_to_json(v) for v in obj]
    elif isinstance(obj, dict):
        return {k: neo4j_to_json(v) for k, v in obj.items()}
    else:
        return obj

@router.get("/")
async def run_cypher_query(
    query: str = Query(..., description="Cypher query to execute (read-only operations only)"),
    limit: Optional[int] = Query(1000, description="Maximum number of records to return", ge=1, le=10000),
    db: Neo4jDatabase = Depends(get_db)
) -> List[Dict[str, Any]]:
    """
    Execute a custom Cypher query against the Neo4j database.
    Only read-only operations are permitted.
    """
    if not query:
        raise HTTPException(status_code=400, detail="Query parameter is required")
    
    # Prevent write operations
    if WRITE_OPERATIONS.search(query) or WRITE_PROCEDURES.search(query):
        raise HTTPException(
            status_code=403, 
            detail="Only read operations are allowed. Write operations such as CREATE, DELETE, SET, etc. are forbidden."
        )
    
    # Add a LIMIT clause if missing
    if "limit" not in query.lower():
        query += f" LIMIT {limit}"
    
    try:
        # Execute query
        results = db.execute_query(query)
        
        # Convert all Neo4j objects to JSON-serializable data
        cleaned_data = [neo4j_to_json(record) for record in results]
        
        return cleaned_data
    
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Error executing query: {str(e)}"
        )