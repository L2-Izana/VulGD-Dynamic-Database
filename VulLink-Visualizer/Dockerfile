# ---------------------------
# Stage 1: Build React App
# ---------------------------
# Stage 1: Build React App
FROM node:20-alpine AS builder
WORKDIR /app

# Accept build arguments
ARG REACT_APP_BACKEND_URL
ARG REACT_APP_NEO4J_URL
ARG REACT_APP_NEO4J_USER
ARG REACT_APP_NEO4J_PASSWORD

# Export to environment so React can use them
ENV REACT_APP_BACKEND_URL=$REACT_APP_BACKEND_URL
ENV REACT_APP_NEO4J_URL=$REACT_APP_NEO4J_URL
ENV REACT_APP_NEO4J_USER=$REACT_APP_NEO4J_USER
ENV REACT_APP_NEO4J_PASSWORD=$REACT_APP_NEO4J_PASSWORD

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install

# Copy source code
COPY . .

# Build React app
RUN npm run build

# ---------------------------
# Stage 2: Serve with Nginx
# ---------------------------
FROM nginx:alpine

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Copy custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy build files from builder stage
COPY --from=builder /app/build /usr/share/nginx/html

# Expose port
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]