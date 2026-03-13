from app.db.database import Neo4jDatabase
import requests
import csv

print("Test 1: Database connetion")
db = Neo4jDatabase()
print("Database connected")
print("Test 2: Custom Query separately")
query="MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 50"
results = db.execute_query(query)
print("Dummy Relationship Query checked")        
query="MATCH (n:Vulnerability) RETURN n LIMIT 25"
results = db.execute_query(query)
print("Dummy Node Query checked")        

print("Test 3: Custom Query API testing")
url = "http://localhost:8000/api/v1/"
query = "MATCH (n:Vulnerability) RETURN n LIMIT 25"
limit = 25

response = requests.get(f"{url}cypher_query", params={"query": query, "limit": limit})

if response.status_code == 200:
    data = response.json()
    assert data and len(data) > 0, f"API endpoint for custom query fails" 
    print(f"API endpoint for Custom Query works, retrieved {len(data)} items.")
else:
    print("Error:", response.status_code, response.text)

print("Test 4: Node Download API testing")
for file_format in ["json", "csv"]:
    print("File format: ", file_format)
    response = requests.get(f"{url}node_download", params={"node_type": "Weakness", "file_format": file_format})

    if response.status_code == 200:

        if file_format == "json":
            data = response.json()
            count = len(data)
            assert count > 0, "API endpoint for node download fails"
            print(f"API endpoint for Node Downloading works, retrieved {count} items.")
        else:
            assert response, f"API endpoint for node download fails"
    else:
        print("Error:", response.status_code, response.text)

print("Test 5: Relationship Download API testing")
for file_format in ["json", "csv"]:
    print("File format: ", file_format)
    response = requests.get(f"{url}relationship_download", params={"relationship_type": "EXPLOITS", "file_format": file_format})

    if response.status_code == 200:
        if file_format == "json":
            data = response.json()
            count = len(data)
            assert count > 0, "API endpoint for node download fails"
            print(f"API endpoint for Node Downloading works, retrieved {count} items.")
        else:
            assert response, f"API endpoint for node download fails"
    else:
        print("Error:", response.status_code, response.text)
        
import requests
import time

URL = "http://localhost:8000/api/v1/llm_embedding"

MODELS = ["mpnet", "fasttext"]
DIMS = [20, 32, 64, 128]

YEAR = 2020  # adjust if needed


def test_embeddings():
    print("Testing LLM Embeddings API\n")

    for model in MODELS:
        for dim in DIMS:

            params = {
                "model": model,
                "year": YEAR,
                "dim_size": dim
            }

            print(f"Testing model={model}, dim={dim}")

            start = time.time()
            response = requests.get(URL, params=params)
            elapsed = round(time.time() - start, 3)

            if response.status_code != 200:
                print("❌ Request failed:", response.status_code)
                print(response.text)
                continue

            data = response.json()

            embeddings = data.get("embeddings", [])
            cve_ids = data.get("cveIDs", [])
            count = data.get("count", 0)

            if count == 0:
                print("⚠ No embeddings returned")
                continue

            # verify dimension
            returned_dim = len(embeddings[0])

            print(
                f"✔ Success | count={count} | returned_dim={returned_dim} | time={elapsed}s"
            )

            assert returned_dim == dim or dim == 128 and returned_dim == 128, \
                f"Dimension mismatch: expected {dim}, got {returned_dim}"

            assert len(cve_ids) == count
            assert len(embeddings) == count

    print("\nAll tests finished.")


if __name__ == "__main__":
    test_embeddings()
    
# Run this to read environment variables
# $env:PYTHONPATH = "."; npx dotenv-cli -e ..\.env.development -- python tests/test_endpoints.py 