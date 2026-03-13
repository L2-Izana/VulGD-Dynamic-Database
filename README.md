# VulLink Visualizer

VulLink Visualizer is an interactive web application for exploring and analyzing vulnerability data through graph visualization. It allows users to query, visualize, and export data from a Neo4j graph database containing vulnerabilities, exploits, products, and their relationships. The system is part of **VulGD: A LLM-Powered Dynamic Open-Access Vulnerability Graph Database**.

---

## Features

### Graph Visualization

* Interactive force-directed graph
* Node coloring by type (Vulnerability, Exploit, Product, etc.)
* Node detail panel
* Animated link particles for relationship highlighting

### Query Interface

* Cypher query editor
* Sample query templates
* Visualization of query results directly in the graph

### Data Export

* **Node Export:** Download node data (Vulnerabilities, Exploits, Products, etc.)
* **Relationship Export:** Download relationships with source/target properties
* Supported formats: **JSON, CSV**

### LLM Integration

* Download pre-embedded vulnerability descriptions
* Configurable embedding dimensions
* Supported formats: **CSV, JSON, PKL**

---

## Prerequisites

* Node.js (v14+)
* Neo4j database with vulnerability data
* Optional backend service for LLM embedding generation

---

## Installation

```bash
cd vullink-visualizer
npm install
```

Add these keys into the `.env` file in the project root:

```env
REACT_APP_NEO4J_URL=bolt://localhost:7687
REACT_APP_NEO4J_USER=neo4j
REACT_APP_NEO4J_PASSWORD=your_password
REACT_APP_BACKEND_URL=http://localhost:5000
```

Start the development server:

```bash
npx dotenv-cli -e ..\.env.development -- npm start # For simplicity, use a global .env
```

---

## Usage

### Graph Exploration

* Open **Sample Queries** to load predefined graph queries
* Click nodes to view detailed information
* Drag nodes to adjust layout

### Custom Queries

* Enter Cypher queries in the query editor
* Click **Run Query**
* Use `LIMIT` to control result size

Example:

```cypher
MATCH (v:Vulnerability)-[r]->(p:Product)
RETURN v, r, p
LIMIT 50
```

### Data Export

1. Go to **Node Download** or **Relationship Download**
2. Select node/relationship type
3. Choose properties
4. Select format (JSON or CSV)
5. Click **Download**

### LLM Embedding Download

1. Open **LLM Integration**
2. Select vulnerability year
3. Choose embedding dimension
4. Select output format
5. Download embeddings

---

## Architecture

Main components:

* **App** – Manages Neo4j connection and application state
* **GraphVisualization** – Force-directed graph rendering (`react-force-graph`)
* **CypherFrame** – Query editor and execution interface
* **ToolsPanel** – Utility tools:

  * SampleVisualization
  * NodeDownload
  * RelationshipDownload
  * LLMIntegration

---

## Data Model

### Node Types

* Vulnerability (CVE)
* Exploit
* Weakness (CWE)
* Product
* Vendor
* Author
* Domain

### Relationship Types

* `AFFECTS` (Vulnerability → Product)
* `REFERS_TO` (Vulnerability → Domain)
* `EXAMPLE_OF` (Vulnerability → Weakness)
* `EXPLOITS` (Exploit → Vulnerability)
* `WRITES` (Author → Exploit)
* `BELONGS_TO` (Product → Vendor)

---

## License

MIT License. See `LICENSE` for details.

---

## Acknowledgments

* Neo4j – Graph database
* React Force Graph – Graph visualization
* D3.js – Force simulation

# VulLink API

A FastAPI-based REST API for the VulLink research project, focused on vulnerability linking and analysis.

## Features

- RESTful API for vulnerability data access and analysis
- Documented endpoints with Swagger UI
- Structured vulnerability data models
- Scalable architecture for research and production use

## Quick Start

1. Clone the repository
2. Create virtual environment with Python=3.12.4 with `python -m venv venv` 
3. Install dependencies: `pip install -r requirements.txt`
4. Run the development server: `npx dotenv-cli -e ..\.env.development -- uvicorn app.main:app --reload` (to read global .env file)
5. Test the endpoints with `$env:PYTHONPATH = "."; npx dotenv-cli -e ..\.env.development -- python tests/test_endpoints.py`
6. Access the API documentation at `http://localhost:8000/docs`

## Deployment
Detailed deployment instructions for VPS environments are included in the `deployment.md` file.
```bash
uvicorn app.main:app --reload
```