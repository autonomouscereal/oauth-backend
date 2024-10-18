#!/bin/bash
# init.sh
set -e

# Initialize PostgreSQL data directory if it doesn't exist
if [ ! -d "/var/lib/postgresql/data" ]; then
    echo "Initializing PostgreSQL data directory..."
    mkdir -p /var/lib/postgresql/data
    chown -R postgres:postgres /var/lib/postgresql
    su-exec postgres initdb -D /var/lib/postgresql/data
fi

# Update pg_hba.conf to allow password authentication
PG_HBA=/var/lib/postgresql/data/pg_hba.conf
if [ -f "$PG_HBA" ]; then
    echo "Configuring PostgreSQL to use md5 authentication..."
    sed -i "s/^#\?\(local\s\+all\s\+all\s\+\)peer/\1md5/" $PG_HBA
    sed -i "s/^#\?\(host\s\+all\s\+all\s\+127\.0\.0\.1\/32\s\+\)md5/\1md5/" $PG_HBA
    sed -i "s/^#\?\(host\s\+all\s\+all\s\+::1\/128\s\+\)md5/\1md5/" $PG_HBA
fi

# Ensure /run/postgresql exists and is owned by postgres
echo "Ensuring /run/postgresql exists and is owned by postgres..."
mkdir -p /run/postgresql
chown postgres:postgres /run/postgresql

# Start PostgreSQL to perform setup
echo "Starting PostgreSQL..."
su-exec postgres postgres -D /var/lib/postgresql/data &
sleep 5

# Create PostgreSQL user with SUPERUSER privilege if it doesn't exist
echo "Creating PostgreSQL user with SUPERUSER privilege if it doesn't exist..."
su-exec postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname = '$db_username'" | grep -q 1 || su-exec postgres psql -c "CREATE USER $db_username WITH PASSWORD '$db_password' SUPERUSER;"

# Create database if it doesn't exist
echo "Creating PostgreSQL database if it doesn't exist..."
su-exec postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = '$OAUTHDB'" | grep -q 1 || su-exec postgres psql -c "CREATE DATABASE $OAUTHDB OWNER $db_username;"

# Grant all privileges on the database to the user
su-exec postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $OAUTHDB TO $db_username;"

# Stop PostgreSQL (Supervisor will manage it)
echo "Stopping PostgreSQL..."
su-exec postgres pg_ctl -D /var/lib/postgresql/data -m fast -w stop
