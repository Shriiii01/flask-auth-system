#!/bin/bash

# Function to cleanup on exit
cleanup() {
    echo "Cleaning up..."
    docker-compose down
    exit 0
}

# Trap SIGINT and SIGTERM
trap cleanup SIGINT SIGTERM

# Check if .env file exists, if not create from example
if [ ! -f .env ]; then
    echo "Creating .env file from .env.example..."
    cp .env.example .env
    echo "Please update the .env file with your actual values."
    exit 1
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Docker is not running. Please start Docker and try again."
    exit 1
fi

# Stop any running containers
echo "Stopping any running containers..."
docker-compose down

# Build the images
echo "Building Docker images..."
docker-compose build

# Start the application
echo "Starting the application..."
docker-compose up -d

# Wait for services to be ready
echo "Waiting for services to be ready..."
attempt=1
max_attempts=30
until docker-compose ps | grep "healthy" | wc -l | grep -q "2" || [ $attempt -gt $max_attempts ]; do
    echo "Waiting for services to be healthy (attempt $attempt/$max_attempts)..."
    sleep 2
    attempt=$((attempt + 1))
done

if [ $attempt -gt $max_attempts ]; then
    echo "Services failed to become healthy within the timeout period"
    docker-compose logs
    cleanup
fi

echo "All services are healthy!"
echo "Application is running at http://localhost:${FLASK_PORT:-5000}"
echo "Swagger UI is available at http://localhost:${FLASK_PORT:-5000}/docs"

# Show logs
echo "Showing application logs..."
docker-compose logs -f 