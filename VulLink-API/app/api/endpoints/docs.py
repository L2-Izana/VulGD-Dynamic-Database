from fastapi import APIRouter
from typing import Dict, Any

router = APIRouter()

@router.get("", summary="Get API documentation info")
async def get_api_docs() -> Dict[str, Any]:
    """
    Get API documentation information including available endpoints,
    data models, and usage examples.
    """
    return {
        "api_version": "1.0.0",
        "title": "VulLink API",
        "description": "API for accessing vulnerability knowledge graph data",
        "endpoints": {
            "docs": {
                "description": "Documentation of query parameters, configurations.",
                "examples": [
                    {"path": "/docs", "description": "This auto‑generated Swagger UI"}
                ]
            },
            "node_download": {
                "description": "Export nodes with selected properties in CSV or JSON format",
                "examples": [
                    {
                        "path": "/node_download/?node_type=Vulnerability&props=cveID,description,v2severity&file_format=csv",
                        "description": "Export vulnerabilities with specific properties as CSV"
                    }
                ]
            },
            "relationship_download": {
                "description": "Export relationship edges with source and target node info",
                "examples": [
                    {
                        "path": "/relationship_download/?relationship_type=AFFECTS&source_props=id,name&target_props=id,name&rel_props=affectedVersion&file_format=json",
                        "description": "Export AFFECTS relationships with version info as JSON"
                    }
                ]
            },
            "cypher_query": {
                "description": "Submit custom read‑only Cypher queries for data retrieval",
                "examples": [
                    {
                        "path": "/cypher_query/?query=MATCH (v:Vulnerability) RETURN v.cveID LIMIT 10",
                        "description": "Get IDs of 10 vulnerabilities"
                    }
                ]
            },
            "llm_embedding": {
                "description": "Retrieve LLM embeddings filtered by year, with specified dimension size and output format",
                "parameters": {
                    "year": "Filter embeddings by CVE publication year (e.g., 2021)",
                    "dim_size": "Dimension size of the embedding vector (e.g., 128 or 32)",
                    "file_format": "Output format: csv or json"
                },
                "examples": [
                    {
                        "path": "/llm_embedding/?year=2021&dim_size=128&file_format=json",
                        "description": "Fetch 128‑dimensional embeddings for CVEs from 2021 as JSON"
                    },
                    {
                        "path": "/llm_embedding/?year=2020&dim_size=32&file_format=csv",
                        "description": "Fetch 32‑dimensional embeddings for CVEs from 2020 as CSV"
                    }
                ]
            }
        },
        "documentation_links": {
            "swagger": "/docs",
            "redoc":   "/redoc"
        }
    }
