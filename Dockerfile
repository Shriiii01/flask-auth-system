# Use an official lightweight Python image
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# Copy and set permissions for the entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Set the entrypoint script
ENTRYPOINT ["docker-entrypoint.sh"]

# Run with Gunicorn in production mode
ENV FLASK_APP=flask_auth
ENV FLASK_ENV=development
ENV FLASK_PORT=5001

EXPOSE 5001

CMD ["gunicorn", "-b", "0.0.0.0:5001", "--workers", "4", "--timeout", "120", "run:app"]