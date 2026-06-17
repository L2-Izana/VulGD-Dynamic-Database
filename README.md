# VulLink: A Dynamic Open-Access Vulnerability Graph Database for Cybersecurity Data Mining

![VulLink System Framework](figures/framework.pdf)

**VulLink** is a deployed, dynamic, and open-access vulnerability graph database specifically designed for cybersecurity data mining. Part of the broader **VulGD** ecosystem, it integrates fragmented vulnerability records from multiple public repositories—including the National Vulnerability Database (NVD), Common Vulnerabilities and Exposures (CVE), Common Weakness Enumeration (CWE), Exploit Database (EDB), and CVE Details—into a unified, continuously updated property graph backed by Neo4j.

This repository contains the full source code for the VulLink system, including the data integration pipeline, the FastAPI backend, the React-based interactive visualizer, system deployment configurations, and downstream evaluation resources. It is prepared to support full reproducibility for our IEEE ICDM 2026 Applied Track submission.

---

# 🏗️ Repository Architecture

The project is modularized into four core components to ensure strict separation of concerns across data engineering, backend services, frontend visualization, and experimental code.

| Component                  | Description                                                                                                                                                    |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **VulLink/**               | Contains system-level configuration, Neo4j database setup utilities, configuration code, deployment scripts, and `analysis.ipynb`.                             |
| **VulLink-API/**           | A FastAPI-based REST application exposing scalable endpoints for Cypher querying, customized subgraph extraction, and pre-computed LLM embedding retrieval.    |
| **VulLink-Visualizer/**    | An interactive React frontend featuring a force-directed graph exploration canvas, a live Cypher query console, and modular data export tools (JSON/CSV).      |
| **VulLink-Data-Pipeline/** | The core ETL and data mining engine containing ingestion, preprocessing, normalization, entity/relation construction, validation, and graph loading pipelines. |

## Root Directory Layout

```text
VulGD-Dynamic-Database/
├── data/                       # Local data storage directory
├── figures/                    # System images and documentation assets
├── VulLink/                    # Configuration and environment scripts
├── VulLink-API/                # Python FastAPI backend
├── VulLink-Data-Pipeline/      # ETL and data mining pipelines
├── VulLink-Visualizer/         # React frontend
├── .env.development            # Shared development environment variables
├── data.tar.gz                 # Compressed snapshot data pack
├── vulkg.tar.gz                # Compressed graph snapshot database archive
└── docker-compose.yml          # Multi-container orchestrator configuration
```

# ⚙️ Prerequisites

To deploy or develop VulLink locally, ensure your machine satisfies the following requirements:

* Docker & Docker Compose (recommended for deployment)
* Python 3.12.4
* Node.js v14+
* Neo4j Community Edition 4.4.11 (if running natively outside Docker)

---

# 🚀 Quick Start: Full System Deployment

For reviewers and users wanting to deploy the complete VulLink stack (Frontend, API, and Graph Database), we provide a containerized Docker workflow.

## 1. Environment Configuration

Create a `.env` file in the project root:

```env
REACT_APP_NEO4J_URL=bolt://localhost:7687
REACT_APP_NEO4J_USER=neo4j
REACT_APP_NEO4J_PASSWORD=your_secure_password
REACT_APP_BACKEND_URL=http://localhost:8000
```

## 2. Launch Container Cluster

Run:

```bash
docker-compose up --build -d
```

### Access Points

* Web Interface: http://localhost:80
* API Documentation (Swagger): http://localhost:8000/docs

---

# 💻 Local Development Setup

If you prefer running individual services separately for development and debugging, follow the instructions below.

> **Note:** Component execution requires `dotenv-cli` to load variables from `.env.development`.

---

## 1. Graph Integration Pipeline (VulLink-Data-Pipeline)

The ETL engine supports incremental updates without rebuilding the graph database from scratch.

Navigate to:

```bash
cd VulLink-Data-Pipeline
```

Configure parameters in:

* `pipeline_config.json`
* `config.py`

Run the pipeline:

```bash
python main.py
```

or individual ingestion modules:

```bash
python nvd_pipeline_new.py
```

> In production deployments, these operations are automatically executed via scheduled CRON jobs.

---

## 2. API Backend Layer (VulLink-API)

Navigate to:

```bash
cd VulLink-API
```

Create and activate a virtual environment:

```bash
python -m venv venv
```

Windows:

```powershell
.\venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Launch the API server:

```bash
npx dotenv-cli -e ..\.env.development -- uvicorn app.main:app --reload
```

Run endpoint tests:

```powershell
$env:PYTHONPATH="."
npx dotenv-cli -e ..\.env.development -- python tests/test_endpoints.py
```

---

## 3. Frontend Visualizer (VulLink-Visualizer)

Navigate to:

```bash
cd VulLink-Visualizer
```

Install dependencies:

```bash
npm install
```

Launch the development server:

```bash
npx dotenv-cli -e ..\.env.development -- npm start
```

---

# 📊 Downstream Data Mining Utility

VulLink enables researchers to bypass raw data ingestion and directly perform:

* Vulnerability analysis
* Exploitability assessment
* Graph mining
* Vulnerability clustering
* Representation learning

## Graph Data & Schema

The current deployed snapshot contains:

* **545,420 nodes**
* **1,660,599 relationships**

### Node Types

* Vulnerability
* Exploit
* Weakness
* Product
* Vendor
* Author
* Domain

### Relationship Types

* AFFECTS
* REFERS_TO
* EXAMPLE_OF
* EXPLOITS
* WRITES
* BELONGS_TO

---

## Pre-computed Semantic Feature Extraction

To facilitate machine learning tasks without requiring expensive local embedding generation, VulLink provides pre-computed vulnerability embeddings generated from:

* SecBERT
* FastText
* all-mpnet-base-v2

Supported PCA dimensions:

* 16
* 32
* 64
* 128
* 256
* 512
* 768

Embeddings can be downloaded through either:

* Web Interface
* API Endpoints

---

# 📝 Citation

If you use VulLink in academic research, please cite:

```bibtex
@article{do2026vullink,
  title={VulLink: A Dynamic Open-Access Vulnerability Graph Database for Cybersecurity Data Mining},
  author={Do, Luat and Cao, Jinli and Yin, Jiao and Wang, Hua},
  journal={arXiv preprint [arXiv:2604.06967](https://arxiv.org/pdf/2604.06967)},
  year={2026}
}
```

---

# 📄 License

This project is released under the MIT License.

Please refer to the LICENSE files within the root repository and individual subprojects for additional licensing information.
