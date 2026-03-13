from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse, JSONResponse
from typing import List, Optional
import io
import csv

from neo4j.time import Date, DateTime, Time

from app.db.database import get_db, Neo4jDatabase

router = APIRouter()


# -----------------------------
# Neo4j value serializer
# -----------------------------
def serialize_value(v):
    if isinstance(v, (Date, DateTime, Time)):
        return str(v)
    if isinstance(v, dict):
        return {k: serialize_value(val) for k, val in v.items()}
    if isinstance(v, list):
        return [serialize_value(i) for i in v]
    return v


@router.get("", summary="Download relationships as CSV or JSON")
async def download_relationships(
    relationship_type: str = Query(..., description="Type of relationship (e.g. AFFECTS)"),
    source_props: Optional[List[str]] = Query(None, description="Source node properties to include"),
    target_props: Optional[List[str]] = Query(None, description="Target node properties to include"),
    rel_props: Optional[List[str]] = Query(None, description="Relationship properties to include"),
    file_format: Optional[str] = Query("csv", regex="^(csv|json)$", description="csv or json"),
    db: Neo4jDatabase = Depends(get_db),
):

    if not relationship_type:
        raise HTTPException(400, "Relationship type is required")

    if file_format not in ["csv", "json"]:
        raise HTTPException(400, "Invalid file format")

    # -----------------------------
    # Build property projections
    # -----------------------------
    src_map = (
        "{ " + ", ".join(f"{p}: src.{p}" for p in source_props) + " }"
        if source_props else
        "properties(src)"
    )

    tgt_map = (
        "{ " + ", ".join(f"{p}: tgt.{p}" for p in target_props) + " }"
        if target_props else
        "properties(tgt)"
    )

    rel_map = (
        "{ " + ", ".join(f"{p}: r.{p}" for p in rel_props) + " }"
        if rel_props else
        "properties(r)"
    )

    # -----------------------------
    # Cypher query
    # -----------------------------
    cypher = f"""
    MATCH (src)-[r:{relationship_type}]->(tgt)
    RETURN
        {src_map} AS source,
        {tgt_map} AS target,
        {rel_map} AS relationship
    """

    records = db.execute_query(cypher)

    if not records:
        raise HTTPException(404, f"No relationships of type {relationship_type} found")

    # -----------------------------
    # Build Python objects
    # -----------------------------
    data = []
    for rec in records:
        data.append({
            "source": serialize_value(rec["source"]),
            "target": serialize_value(rec["target"]),
            "relationship": serialize_value(rec["relationship"]),
        })

    # -----------------------------
    # JSON export
    # -----------------------------
    if file_format == "json":
        resp = JSONResponse(content=data)
        resp.headers["Content-Disposition"] = (
            f"attachment; filename={relationship_type}_relationships.json"
        )
        return resp

    # -----------------------------
    # CSV export
    # -----------------------------

    # collect all possible columns
    cols = set()
    for row in data:
        cols |= {f"src_{k}" for k in row["source"].keys()}
        cols |= {f"tgt_{k}" for k in row["target"].keys()}
        cols |= {f"rel_{k}" for k in row["relationship"].keys()}

    fieldnames = sorted(cols)

    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=fieldnames)
    writer.writeheader()

    for row in data:
        flat = {}

        flat.update({f"src_{k}": v for k, v in row["source"].items()})
        flat.update({f"tgt_{k}": v for k, v in row["target"].items()})
        flat.update({f"rel_{k}": v for k, v in row["relationship"].items()})

        writer.writerow(flat)

    stream.seek(0)

    resp = StreamingResponse(iter([stream.getvalue()]), media_type="text/csv")
    resp.headers["Content-Disposition"] = (
        f"attachment; filename={relationship_type}_relationships.csv"
    )

    return resp