#!/bin/bash

# Function to wait for Redis
wait_for_redis() {
    echo "Waiting for Redis..."
    while ! nc -z redis 6379; do
        sleep 1
    done
    echo "Redis is ready!"
}

# Wait for Redis to be ready
wait_for_redis

# Execute the main command
exec "$@" 