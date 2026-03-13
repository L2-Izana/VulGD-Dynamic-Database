#!/bin/bash
# ---------------------------------------------------------------------------
# This script installs Node.js dependencies, builds the React application,
# and configures Nginx to serve the production build of the React app.
#
# Assumptions:
# - The React app is located in /home/ubuntu/VulLink-Visualizer.
# - The production build is generated in the "build" folder.
# - Nginx is installed on the VPS.
#
# Make sure to run this script with a user that has sudo privileges.
# ---------------------------------------------------------------------------

# Define the path to the Nginx configuration file for the default site.
NGINX_CONFIG="/etc/nginx/sites-available/default"

# ---------------------------------------------------------------------------
# Step 1: Install Node.js Dependencies
# ---------------------------------------------------------------------------
echo "Installing Node.js dependencies..."
# Change to the project directory.
cd /home/ubuntu/VulLink-Visualizer
# Install all dependencies specified in package.json.
npm install

# ---------------------------------------------------------------------------
# Step 2: Build the React Application
# ---------------------------------------------------------------------------
echo "Building the React app..."
# Run the build command defined in package.json.
npm run build

# ---------------------------------------------------------------------------
# Step 3: Update Nginx Configuration
# ---------------------------------------------------------------------------
echo "Updating Nginx configuration to serve the React app from /home/ubuntu/VulLink-Visualizer/build..."
# Update the default Nginx configuration file to serve the React build.
# This configuration sets up a basic server block that listens on port 80
# and serves the static files from the build folder.
sudo bash -c "cat > $NGINX_CONFIG" <<EOL
server {
    # Listen on IPv4 and IPv6 on port 80 as the default server.
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;  # Catch-all server name.

    # Specify the root directory where the built React app is located.
    root /home/ubuntu/VulLink-Visualizer/build;
    # Define the default files to serve.
    index index.html index.htm;

    # Handle routing for client-side routing.
    # If a file is not found, fallback to serving index.html.
    location / {
        try_files \$uri /index.html;
    }
}
EOL

# ---------------------------------------------------------------------------
# Step 4: Reload Nginx to Apply Changes
# ---------------------------------------------------------------------------
echo "Reloading Nginx..."
# Restart Nginx to apply the new configuration.
sudo systemctl restart nginx

echo "Deployment complete. Your React app is now served by Nginx."
