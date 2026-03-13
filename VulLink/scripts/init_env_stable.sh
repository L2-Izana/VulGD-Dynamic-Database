#!/bin/bash
# Exit immediately if any command exits with a non-zero status.
set -e

PROJECT_DIR=/home/ubuntu/VulGD-Dynamic-Database
API_REQUIREMENTS_FILE=./VulLink-API/requirements.txt

# ============================================================================
# Update system packages
# ============================================================================
echo "=============================="
echo "Updating the system packages..."
echo "=============================="
sudo apt update && sudo apt upgrade -y

# ============================================================================
# Install base packages: curl, wget, git, etc.
# ============================================================================
echo "=============================================="
echo "Installing base packages (curl, wget, git, etc.)..."
echo "=============================================="
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common wget gnupg git

# ============================================================================
# Add the Neo4j repository for Neo4j 4.4
# ============================================================================
echo "=============================="
echo "Adding the Neo4j repository for Neo4j 4.4..."
echo "=============================="
# Import the Neo4j GPG key
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
# Add the repository to the system sources list
echo 'deb https://debian.neo4j.com stable 4.4' | sudo tee /etc/apt/sources.list.d/neo4j.list
# Update package lists after adding the new repository
sudo apt update

# ============================================================================
# Install Neo4j and enable its service
# ============================================================================
echo "=============================="
echo "Installing Neo4j..."
echo "=============================="
sudo apt install -y neo4j
echo "Starting and enabling Neo4j service..."
sudo systemctl start neo4j
sudo systemctl enable neo4j

# ============================================================================
# Configure Neo4j for public HTTP access
# ============================================================================
echo "=========================================="
echo "Configuring Neo4j for public HTTP access..."
echo "=========================================="
NEO4J_CONFIG="/etc/neo4j/neo4j.conf"

# Uncomment and update settings to allow connections from any IP
sudo sed -i 's/#dbms.default_listen_address=0.0.0.0/dbms.default_listen_address=0.0.0.0/' $NEO4J_CONFIG
sudo sed -i 's/#dbms.connector.http.listen_address=:7474/dbms.connector.http.listen_address=0.0.0.0:7474/' $NEO4J_CONFIG
sudo sed -i 's/#dbms.connector.bolt.listen_address=:7687/dbms.connector.bolt.listen_address=0.0.0.0:7687/' $NEO4J_CONFIG

# Ensure these settings are present by appending them if they aren't found
sudo grep -q '^dbms.default_listen_address=0.0.0.0' $NEO4J_CONFIG || echo 'dbms.default_listen_address=0.0.0.0' | sudo tee -a $NEO4J_CONFIG
sudo grep -q '^dbms.connector.http.listen_address=0.0.0.0:7474' $NEO4J_CONFIG || echo 'dbms.connector.http.listen_address=0.0.0.0:7474' | sudo tee -a $NEO4J_CONFIG
sudo grep -q '^dbms.connector.bolt.listen_address=0.0.0.0:7687' $NEO4J_CONFIG || echo 'dbms.connector.bolt.listen_address=0.0.0.0:7687' | sudo tee -a $NEO4J_CONFIG

# ============================================================================
# Install the APOC plugin for Neo4j
# ============================================================================
echo "====================================="
echo "Installing the APOC plugin for Neo4j..."
echo "====================================="
# Change directory to the Neo4j plugins folder
cd /var/lib/neo4j/plugins
# Download the APOC plugin jar file (adjust the version if needed)
sudo wget https://github.com/neo4j-contrib/neo4j-apoc-procedures/releases/download/4.4.0.35/apoc-4.4.0.35-all.jar
# Return to the home directory
cd $PROJECT_DIR

# ============================================================================
# Restart Neo4j to apply configuration changes
# ============================================================================
echo "Restarting Neo4j to apply configuration changes..."
sudo systemctl restart neo4j

# ============================================================================
# Install Node.js (v16 LTS) and npm
# ============================================================================
echo "====================================="
echo "Installing Node.js (v16 LTS) and npm..."
echo "====================================="
# Setup the NodeSource repository for Node.js v16
curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
# Install Node.js and npm
sudo apt-get install -y nodejs

# Return to the home directory for further operations
cd $PROJECT_DIR

# ============================================================================
# Install Python3, pip3, and python3-venv packages
# ============================================================================
echo "=================================================="
echo "Installing Python3, pip3, and python3-venv packages..."
echo "=================================================="
sudo apt install -y python3 python3-pip python3-venv

# ============================================================================
# Create and configure a Python virtual environment
# ============================================================================
echo "=================================================="
echo "Creating a Python virtual environment at venv..."
echo "=================================================="
python3 -m venv $PROJECT_DIR/venv

echo "=================================================="
echo "Activating virtual environment and installing Python dependencies..."
echo "=================================================="
# Activate the virtual environment
source $PROJECT_DIR/venv/bin/activate
# Upgrade pip to the latest version
pip install --upgrade pip
# Install necessary Python packages:
pip install -r $API_REQUIREMENTS_FILE

# ============================================================================
# Final Message
# ============================================================================
echo "=================================================="
echo "EC2 initialization complete!"
echo "=================================================="
