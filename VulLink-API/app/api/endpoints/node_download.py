from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse, JSONResponse
from typing import List, Optional
import io, csv
from neo4j.time import Date, DateTime

from app.db.database import get_db, Neo4jDatabase

router = APIRouter()

NODE_TYPES = ["Vulnerability", "Exploit", "Author", "Weakness", "Product", "Domain"]

def neo4j_to_json(obj):
    """Recursively convert Neo4j values to JSON-serializable Python objects"""
    if isinstance(obj, (Date, DateTime)):
        return obj.iso_format()
    elif isinstance(obj, list):
        return [neo4j_to_json(v) for v in obj]
    elif isinstance(obj, dict):
        return {k: neo4j_to_json(v) for k, v in obj.items()}
    else:
        return obj

@router.get("", summary="Download nodes as CSV or JSON")
async def download_nodes(
    node_type: str = Query(..., description="Type of node (e.g. Vulnerability)"),
    props: Optional[List[str]] = Query(None, description="Properties to export; if omitted, all properties"),
    file_format: Optional[str] = Query("csv", regex="^(csv|json)$", description="csv or json"),
    db: Neo4jDatabase = Depends(get_db),
):
    if node_type not in NODE_TYPES:
        raise HTTPException(400, f"Invalid node type: {node_type}")
        
    # Build RETURN clause
    if props:
        map_proj = "{ " + ", ".join(f"{p}: n.{p}" for p in props) + " }"
    else:
        map_proj = "properties(n)"

    cypher = f"""
    MATCH (n:{node_type})
    RETURN {map_proj} AS props
    """

    records = db.execute_query(cypher)
    if not records:
        raise HTTPException(404, f"No {node_type} nodes found")

    # Unpack and recursively convert all values to JSON-serializable
    data = [neo4j_to_json(rec["props"]) for rec in records]

    if file_format == "json":
        resp = JSONResponse(content=data)
        resp.headers["Content-Disposition"] = f"attachment; filename={node_type}_data.json"
        return resp

    # CSV export
    fieldnames = props or list(data[0].keys())
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=fieldnames)
    writer.writeheader()
    for row in data:
        writer.writerow({fn: row.get(fn, "") for fn in fieldnames})
    stream.seek(0)

    resp = StreamingResponse(iter([stream.getvalue()]), media_type="text/csv")
    resp.headers["Content-Disposition"] = f"attachment; filename={node_type}_data.csv"
    return resp