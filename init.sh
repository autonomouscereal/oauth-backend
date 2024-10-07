#!/bin/bash
set -e

# Define PostgreSQL version
PG_VERSION=11

# Paths
POSTGRES_BIN_DIR="/usr/lib/postgresql/${PG_VERSION}/bin"

# Initialize PostgreSQL data directory if it doesn't exist
if [ ! -d "/var/lib/postgresql/data" ]; then
    echo "Initializing PostgreSQL data directory..."
    mkdir -p /var/lib/postgresql/data
    chown -R postgres:postgres /var/lib/postgresql
    su postgres -c "${POSTGRES_BIN_DIR}/initdb -D /var/lib/postgresql/data"
fi

# Update pg_hba.conf to allow password authentication
PG_HBA=/var/lib/postgresql/data/pg_hba.conf
if [ -f "$PG_HBA" ]; then
    echo "Configuring PostgreSQL to use md5 authentication..."
    sed -i "s/^\(local\s\+all\s\+all\s\+\)peer/\1md5/" $PG_HBA
fi

# Start PostgreSQL to perform setup
echo "Starting PostgreSQL..."
su postgres -c "${POSTGRES_BIN_DIR}/pg_ctl -D /var/lib/postgresql/data -w start"

# Create PostgreSQL user with SUPERUSER privilege if it doesn't exist
echo "Creating PostgreSQL user with SUPERUSER privilege if it doesn't exist..."
su postgres -c "psql -tc \"SELECT 1 FROM pg_roles WHERE rolname = '$db_username'\" | grep -q 1 || psql -c \"CREATE USER $db_username WITH PASSWORD '$db_password' SUPERUSER;\""

# Create database if it doesn't exist
echo "Creating PostgreSQL database if it doesn't exist..."
su postgres -c "psql -tc \"SELECT 1 FROM pg_database WHERE datname = '$OAUTHDB'\" | grep -q 1 || psql -c \"CREATE DATABASE $OAUTHDB OWNER $db_username;\""

# Grant all privileges on the database to the user (redundant but ensures full access)
su postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE $OAUTHDB TO $db_username;\""

# Stop PostgreSQL (Supervisor will manage it)
echo "Stopping PostgreSQL..."
su postgres -c "${POSTGRES_BIN_DIR}/pg_ctl -D /var/lib/postgresql/data -m fast -w stop"
