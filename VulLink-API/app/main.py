from fastapi import FastAPI, APIRouter
from fastapi.middleware.cors import CORSMiddleware
import logging
import os
from app.api import llm_embedding
from app.api.endpoints import node_download, relationship_download, cypher_query, docs

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

app = FastAPI(
    title="VulLink API",
    description="""
    VulLink is a dynamic open-access vulnerability knowledge graph designed to provide 
    intelligent real-time insights about cybersecurity vulnerabilities.
    
    This API provides access to comprehensive vulnerability data, including exploits, 
    weaknesses, affected products, vendors, and their relationships.
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update this with allowed origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create main API router
api_router = APIRouter(prefix="/api/v1")

api_router.include_router(
    llm_embedding.router, prefix="/llm_embedding", tags=["embeddings"]
)

api_router.include_router(
    node_download.router, prefix="/node_download", tags=["Node Export"]
)

api_router.include_router(
    relationship_download.router, prefix="/relationship_download", tags=["Relationship Export"]
)

api_router.include_router(
    cypher_query.router, prefix="/cypher_query", tags=["Custom Queries"]
)

api_router.include_router(
    docs.router, prefix="/docs", tags=["API Documentation"]
)

# Include the API router
app.include_router(api_router)

# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    return {
        "name": "VulLink API",
        "version": "1.0.0",
        "description": "API for accessing vulnerability knowledge graph data",
        "documentation": "/docs",
    }

if __name__ == "__main__":
    import uvicorn
    import platform
    
    # Check if running from reloader or directly
    is_reloaded = os.environ.get("PYTHONPATH", "").endswith("uvicorn")
    
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    
    # Use reload only in development and not in reloader process
    IS_LINUX = platform.system().lower() == 'linux'
    reload = not IS_LINUX and not is_reloaded
    
    uvicorn.run("app.main:app", host=host, port=port, reload=reload) 