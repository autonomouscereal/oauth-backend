# Use the official Python image with slim variant
FROM python:3.9-slim-buster

# Set environment variables directly in the Dockerfile
ENV db_username=postgres
ENV db_password=your_postgres_password
ENV SECRET_KEY=your_secret_key
ENV DB_HOST=localhost
ENV DB_PORT=5432
ENV OAUTHDB=OAUTHDB

# Set the working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
build-essential \
libpq-dev \
postgresql \
postgresql-contrib \
&& rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Supervisor using pip for Python 3
RUN pip install supervisor

# Copy the application code
COPY . .

# Copy and set up Supervisor configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Copy the initialization script
COPY init.sh /init.sh
RUN chmod +x /init.sh

# Ensure the logs directory exists
RUN mkdir -p /var/log/postgresql && mkdir -p /var/log/fastapi

# Expose port 3100
EXPOSE 3100

# Entrypoint to initialize PostgreSQL and start Supervisor
ENTRYPOINT ["/bin/bash", "-c", "/init.sh && supervisord -n -c /etc/supervisor/conf.d/supervisord.conf"]
