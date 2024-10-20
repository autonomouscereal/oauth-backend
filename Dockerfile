# Base image
FROM python:3.9-alpine

# Set environment variables directly in the Dockerfile
ENV db_username=postgres
ENV db_password=your_postgres_password
ENV SECRET_KEY=your_secret_key
ENV DB_HOST=localhost
ENV DB_PORT=5432
ENV OAUTHDB=OAUTHDB
ENV ENVIRONMENT=production

# Set the working directory
WORKDIR /app

# Install system dependencies
RUN apk add --no-cache \
    bash \
    build-base \
    gcc \
    linux-headers \
    musl-dev \
    postgresql \
    postgresql-contrib \
    postgresql-dev \
    python3-dev \
    supervisor \
    nginx \
    openssl \
    su-exec \
    curl \
    net-tools

# Copy the application code
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy Nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Copy SSL certificates
COPY certs/server.crt /etc/ssl/certs/server.crt
COPY certs/server.key /etc/ssl/private/server.key

# Copy init.sh
COPY init.sh /init.sh
RUN chmod +x /init.sh

# Copy supervisord.conf
COPY supervisord.conf /etc/supervisord.conf

# Ensure the logs directory exists
RUN mkdir -p /var/log/postgresql && mkdir -p /var/log/fastapi

# Expose port 443 for HTTPS
EXPOSE 443

# Set environment variables again (if needed)
ENV db_username=postgres
ENV db_password=your_postgres_password
ENV SECRET_KEY=your_secret_key
ENV DB_HOST=localhost
ENV DB_PORT=5432
ENV OAUTHDB=OAUTHDB

# Entrypoint to initialize PostgreSQL and start Supervisor
ENTRYPOINT ["/bin/bash", "-c", "/init.sh && supervisord -n -c /etc/supervisord.conf"]
