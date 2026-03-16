#!/bin/bash

# Set Variables
PROJECT_DIR=/home/ubuntu/VulGD-Dynamic-Database
ENV_FILE=$PROJECT_DIR/.env.development
VULGD_DATA_DIR=$PROJECT_DIR/data/vulkg
NEO4J_IMPORT=/var/lib/neo4j/import
NEO4J_CONF=/etc/neo4j/neo4j.conf
CYPHER_SCRIPT=$PROJECT_DIR/VuLink/src/neo4j/VulKG_Deployment_Cypher.cypher
VULNODES_PROCESSING_SCRIPT=$PROJECT_DIR/VuLink/src/neo4j/vulnodes_preprocessing.py

# --- 2. EXTRACT CREDENTIALS FROM .ENV ---
# This looks for the line starting with NEO4J_USER and grabs the value
USER=$(grep "NEO4J_USER=" $ENV_FILE | cut -d'=' -f2 | tr -d '\r')
PASS=$(grep "NEO4J_PASSWORD=" $ENV_FILE | cut -d'=' -f2 | tr -d '\r')

# --- 3. MOVE DATA ---
echo "Moving CSV files to Neo4j import directory..."
sudo cp $VULGD_DATA_DIR/*.csv $NEO4J_IMPORT/
sudo chown neo4j:neo4j $NEO4J_IMPORT/*.csv
sudo chmod 644 $NEO4J_IMPORT/*.csv
echo "apoc.import.file.enabled=true" | sudo tee -a /etc/neo4j/apoc.conf

# --- 4. OPTIMIZE NEO4J ---
echo "Updating Neo4j memory settings..."
sudo sed -i 's/^#*dbms.memory.heap.initial_size=.*/dbms.memory.heap.initial_size=1G/' $NEO4J_CONF
sudo sed -i 's/^#*dbms.memory.heap.max_size=.*/dbms.memory.heap.max_size=2G/' $NEO4J_CONF
sudo sed -i 's/^#*dbms.memory.pagecache.size=.*/dbms.memory.pagecache.size=1G/' $NEO4J_CONF

# --- 5. RESTART & IMPORT ---
echo "Restarting Neo4j..."
sudo systemctl restart neo4j
sleep 10

# 5.1. Clean the VulNodes dataset by python 
echo "Cleaning VulnerabilityNodes CSV..."
python $VULNODES_PROCESSING_SCRIPT $VULGD_DATA_DIR

echo "Running Cypher import..."
cypher-shell -u "$USER" -p "$PASS" -f "$CYPHER_SCRIPT"

echo "Done!"
