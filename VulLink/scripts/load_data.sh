#!/bin/bash

# Set Variables
DATA_SOURCE="../src/datasource"
NEO4J_IMPORT="/var/lib/neo4j/import"
NEO4J_CONF="/etc/neo4j/neo4j.conf"
CYPHER_SCRIPT="../src/neo4j/VulLink_Data_Load.cypher"

# Move CSV Files to Neo4j Import Directory
echo "Moving CSV files from $DATA_SOURCE to $NEO4J_IMPORT..."
# sudo mv $DATA_SOURCE/*.csv $NEO4J_IMPORT/
sudo chown neo4j:neo4j $NEO4J_IMPORT/*.csv
sudo chmod 644 $NEO4J_IMPORT/*.csv

# Update Java Heap Settings for Neo4j
echo "Optimizing Java heap settings..."
sudo sed -i 's/^#*dbms.memory.heap.initial_size=.*/dbms.memory.heap.initial_size=1G/' $NEO4J_CONF
sudo sed -i 's/^#*dbms.memory.heap.max_size=.*/dbms.memory.heap.max_size=2G/' $NEO4J_CONF
sudo sed -i 's/^#*dbms.memory.pagecache.size=.*/dbms.memory.pagecache.size=1G/' $NEO4J_CONF

# Restart Neo4j to Apply Changes
echo "Restarting Neo4j service..."
sudo systemctl restart neo4j
sleep 10

# Execute Cypher Import Script
echo "Importing data into Neo4j from $CYPHER_SCRIPT..."
cypher-shell -u neo4j -p Vanly180705! -f $CYPHER_SCRIPT

echo "✅ Data import completed successfully!"
