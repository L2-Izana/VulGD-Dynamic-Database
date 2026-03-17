#!/bin/bash

set -euo pipefail

echo "========================================="
echo "VulGD Full Stack Deployment Starting..."
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
# Deploy
# ---------------------------
echo "Stopping existing containers..."
docker-compose down

echo "Building and starting services..."
docker-compose up -d --build

# ---------------------------
# Post-deployment check
# ---------------------------
echo "Checking service health..."

sleep 5

if curl -s http://localhost:8000/docs > /dev/null; then
    echo "Backend is up"
else
    echo "WARNING: Backend not responding yet"
fi

if curl -s http://localhost | grep -q "<!doctype html>"; then
    echo "Frontend is up"
else
    echo "WARNING: Frontend not responding yet"
fi

echo "========================================="
echo "Deployment complete"
echo "Frontend: http://<your-vps-ip>"
echo "Backend:  http://<your-vps-ip>:8000/docs"
echo "========================================="