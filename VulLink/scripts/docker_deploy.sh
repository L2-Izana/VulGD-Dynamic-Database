#!/bin/bash
set -euo pipefail
# Export React build-time env vars
export $(grep -v '^#' ./VulLink-Visualizer/.env | xargs)
echo "========================================="
echo "VulGD Full Stack Full Rebuild Deployment"
echo "========================================="

PROJECT_DIR=/home/ubuntu/VulGD-Dynamic-Database
cd "$PROJECT_DIR"

# ---------------------------
# Validate required files
# ---------------------------
if [ ! -f "./docker-compose.yml" ]; then
    echo "ERROR: docker-compose.yml not found in root"
    exit 1
fi

if [ ! -f "./VulLink-API/.env" ]; then
    echo "ERROR: Backend .env missing"
    exit 1
fi

if [ ! -f "./VulLink-Visualizer/.env" ]; then
    echo "ERROR: Frontend .env missing"
    exit 1
fi

echo "Environment validation passed."

# ---------------------------
# Ensure Docker is running
# ---------------------------
if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Docker is not running"
    exit 1
fi

# ---------------------------
# Full cleanup
# ---------------------------
echo "Stopping and removing all containers, images, volumes, and orphans..."
docker-compose down --rmi all -v --remove-orphans

# ---------------------------
# Build everything from scratch
# ---------------------------
echo "Building all services from scratch..."
docker-compose build --no-cache

# ---------------------------
# Start services
# ---------------------------
echo "Starting services..."
docker-compose up -d

# ---------------------------
# Wait for backend to be ready
# ---------------------------
echo "Waiting for backend to be ready..."
BACKEND_URL="http://localhost:8000/docs"
MAX_WAIT=60
WAITED=0

until curl -s "$BACKEND_URL" > /dev/null; do
    sleep 2
    WAITED=$((WAITED+2))
    if [ "$WAITED" -ge "$MAX_WAIT" ]; then
        echo "WARNING: Backend not responding after $MAX_WAIT seconds"
        break
    fi
done

# ---------------------------
# Check frontend
# ---------------------------
echo "Checking frontend..."
FRONTEND_URL="http://localhost"
if curl -s "$FRONTEND_URL" | grep -q "<!doctype html>"; then
    echo "Frontend is up"
else
    echo "WARNING: Frontend not responding yet"
fi

echo "========================================="
echo "Full rebuild deployment complete"
echo "Frontend: http://<your-vps-ip>"
echo "Backend:  http://<your-vps-ip>:8000/docs"
echo "========================================="