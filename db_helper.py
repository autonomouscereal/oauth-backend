# db_helper.py
import logging

import asyncpg
from datetime import datetime
from credential_manager import CredentialManager

# Configure logging to output to stdout

logger = logging.getLogger(__name__)

class DBHelper:
    def __init__(self):
        self.credentials = CredentialManager.get_db_credentials()
        self.pool = None  # To be initialized in init_db

    async def connect_create_if_not_exists(self, user, database, password, port, host):
        """
        Connect to the specified database. If it doesn't exist, connect to 'postgres' and create it.
        """
        logger.info(f"Attempting to connect to database '{database}' as user '{user}' at {host}:{port}")
        try:
            self.pool = await asyncpg.create_pool(
                user=user,
                password=password,
                database=database,
                host=host,
                port=port,
                min_size=1,
                max_size=10
            )
            logger.info(f"Successfully connected to database '{database}' as user '{user}'")
        except asyncpg.exceptions.InvalidCatalogNameError:
            logger.warning(f"Database '{database}' does not exist. Attempting to create it.")
            try:
                # Connect to the default 'postgres' database to create the new database
                sys_pool = await asyncpg.create_pool(
                    user=user,
                    password=password,
                    database='postgres',
                    host=host,
                    port=port,
                    min_size=1,
                    max_size=5
                )
                async with sys_pool.acquire() as conn:
                    await conn.execute(f'CREATE DATABASE "{database}" OWNER "{user}"')
                    logger.info(f"Database '{database}' created successfully with owner '{user}'")
                await sys_pool.close()
                # Re-attempt connection to the newly created database
                self.pool = await asyncpg.create_pool(
                    user=user,
                    password=password,
                    database=database,
                    host=host,
                    port=port,
                    min_size=1,
                    max_size=10
                )
                logger.info(f"Successfully connected to newly created database '{database}'")
            except Exception as e:
                logger.error(f"Failed to create database '{database}': {e}")
                raise
        except Exception as e:
            logger.error(f"Failed to connect to database '{database}' as user '{user}': {e}")
            raise

    async def init_db(self):
        """
        Initialize the database by ensuring it exists and creating necessary tables.
        """
        user = self.credentials['user']
        database = self.credentials['database']
        password = self.credentials['password']
        port = self.credentials['port']
        host = self.credentials['host']

        logger.info("Starting database initialization process.")

        # Connect to the database, create if not exists
        await self.connect_create_if_not_exists(
            user=user,
            database=database,
            password=password,
            port=port,
            host=host
        )

        async with self.pool.acquire() as conn:
            try:
                # Begin transaction
                await conn.execute("BEGIN;")

                # Create tables with logging
                tables = {
                    "users": """
                        CREATE TABLE IF NOT EXISTS users (
                            id SERIAL PRIMARY KEY,
                            email VARCHAR UNIQUE NOT NULL,
                            hashed_password VARCHAR NOT NULL,
                            created_at TIMESTAMPTZ DEFAULT NOW()
                        );
                    """,
                    "oauth2_clients": """
                        CREATE TABLE IF NOT EXISTS oauth2_clients (
                            client_id VARCHAR PRIMARY KEY,
                            client_secret VARCHAR NOT NULL,
                            redirect_uris TEXT NOT NULL,
                            created_at TIMESTAMPTZ DEFAULT NOW()
                        );
                    """,
                    "oauth2_authorization_codes": """
                        CREATE TABLE IF NOT EXISTS oauth2_authorization_codes (
                            code VARCHAR PRIMARY KEY,
                            client_id VARCHAR REFERENCES oauth2_clients(client_id),
                            redirect_uri VARCHAR,
                            scope VARCHAR,
                            user_id INTEGER REFERENCES users(id),
                            code_challenge VARCHAR,
                            code_challenge_method VARCHAR,
                            expires_at TIMESTAMPTZ
                        );
                    """,
                    "refresh_tokens": """
                        CREATE TABLE IF NOT EXISTS refresh_tokens (
                            token VARCHAR PRIMARY KEY,
                            user_id INTEGER REFERENCES users(id),
                            expires_at TIMESTAMPTZ
                        );
                    """,
                    "Roles": """
                        CREATE TABLE IF NOT EXISTS Roles (
                            id SERIAL PRIMARY KEY,
                            role_name VARCHAR UNIQUE NOT NULL
                        );
                    """,
                    "Permissions": """
                        CREATE TABLE IF NOT EXISTS Permissions (
                            id SERIAL PRIMARY KEY,
                            permission_name VARCHAR UNIQUE NOT NULL
                        );
                    """,
                    "RolePermissions": """
                        CREATE TABLE IF NOT EXISTS RolePermissions (
                            role_id INTEGER REFERENCES Roles(id),
                            permission_id INTEGER REFERENCES Permissions(id),
                            PRIMARY KEY (role_id, permission_id)
                        );
                    """,
                    "UserRoles": """
                        CREATE TABLE IF NOT EXISTS UserRoles (
                            user_id INTEGER REFERENCES users(id),
                            role_id INTEGER REFERENCES Roles(id),
                            PRIMARY KEY (user_id, role_id)
                        );
                    """
                }

                for table_name, create_stmt in tables.items():
                    logger.info(f"Creating table '{table_name}' if it does not exist.")
                    await conn.execute(create_stmt)
                    logger.info(f"Table '{table_name}' is ready.")

                # Commit the transaction
                await conn.execute("COMMIT;")
                logger.info("Database initialization completed successfully.")

            except Exception as e:
                logger.error(f"Error during database initialization: {e}")
                await conn.execute("ROLLBACK;")
                raise

    async def get_db_connection(self):
        """
        Acquire a connection from the pool.
        """
        try:
            conn = await self.pool.acquire()
            logger.info(f"Acquired connection from the pool.")
            return conn
        except Exception as e:
            logger.error(f"Failed to acquire database connection from pool: {e}")
            raise

    async def close_pool(self):
        """
        Close the connection pool.
        """
        if self.pool:
            await self.pool.close()
            logger.info("Database connection pool closed.")

    # User methods
    async def add_user(self, email: str, hashed_password: str):
        async with self.pool.acquire() as conn:
            try:
                await conn.execute("""
                INSERT INTO users (email, hashed_password) VALUES ($1, $2)
                """, email, hashed_password)
                logger.info(f"Added new user with email: {email}")
            except asyncpg.exceptions.UniqueViolationError:
                logger.warning(f"User with email '{email}' already exists.")
            except Exception as e:
                logger.error(f"Error adding user '{email}': {e}")
                raise

    async def get_user_by_email(self, email: str):
        async with self.pool.acquire() as conn:
            user = await conn.fetchrow("SELECT * FROM users WHERE email = $1", email)
            logger.info(f"Fetched user by email '{email}': {'Found' if user else 'Not Found'}")
            return dict(user) if user else None

    async def get_user_by_id(self, user_id: int):
        async with self.pool.acquire() as conn:
            user = await conn.fetchrow("SELECT * FROM users WHERE id = $1", user_id)
            logger.info(f"Fetched user by ID '{user_id}': {'Found' if user else 'Not Found'}")
            return dict(user) if user else None

    # Client methods
    async def get_client_by_id(self, client_id: str):
        async with self.pool.acquire() as conn:
            client = await conn.fetchrow("SELECT * FROM oauth2_clients WHERE client_id = $1", client_id)
            logger.info(f"Fetched OAuth2 client by ID '{client_id}': {'Found' if client else 'Not Found'}")
            return dict(client) if client else None

    async def add_client(self, client_id, client_secret, redirect_uris):
        async with self.pool.acquire() as conn:
            try:
                await conn.execute('''
                    INSERT INTO oauth2_clients (client_id, client_secret, redirect_uris)
                    VALUES ($1, $2, $3)
                ''', client_id, client_secret, redirect_uris)
                logger.info(f"Added OAuth2 client with ID: {client_id}")
            except asyncpg.exceptions.UniqueViolationError:
                logger.warning(f"OAuth2 client with ID '{client_id}' already exists.")
            except Exception as e:
                logger.error(f"Error adding client '{client_id}': {e}")
                raise

    # Authorization code methods
    async def save_authorization_code(self, auth_code):
        async with self.pool.acquire() as conn:
            try:
                await conn.execute("""
                INSERT INTO oauth2_authorization_codes (
                    code, client_id, redirect_uri, scope, user_id, code_challenge, code_challenge_method, expires_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """, auth_code.code, auth_code.client_id, auth_code.redirect_uri, auth_code.scope,
                    auth_code.user_id, auth_code.code_challenge, auth_code.code_challenge_method, auth_code.expires_at)
                logger.info(f"Saved authorization code '{auth_code.code}' for client '{auth_code.client_id}' and user '{auth_code.user_id}'")
            except asyncpg.exceptions.UniqueViolationError:
                logger.warning(f"Authorization code '{auth_code.code}' already exists.")
            except Exception as e:
                logger.error(f"Error saving authorization code '{auth_code.code}': {e}")
                raise

    async def get_authorization_code(self, code: str):
        async with self.pool.acquire() as conn:
            auth_code = await conn.fetchrow("SELECT * FROM oauth2_authorization_codes WHERE code = $1", code)
            logger.info(f"Fetched authorization code '{code}': {'Found' if auth_code else 'Not Found'}")
            return dict(auth_code) if auth_code else None

    async def delete_authorization_code(self, code: str):
        async with self.pool.acquire() as conn:
            try:
                await conn.execute("DELETE FROM oauth2_authorization_codes WHERE code = $1", code)
                logger.info(f"Deleted authorization code '{code}'")
            except Exception as e:
                logger.error(f"Error deleting authorization code '{code}': {e}")
                raise

    # Refresh token methods
    async def save_refresh_token(self, user_id: int, token: str, expires_at: datetime):
        async with self.pool.acquire() as conn:
            try:
                await conn.execute("""
                INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)
                """, token, user_id, expires_at)
                logger.info(f"Saved refresh token '{token}' for user ID '{user_id}'")
            except asyncpg.exceptions.UniqueViolationError:
                logger.warning(f"Refresh token '{token}' already exists.")
            except Exception as e:
                logger.error(f"Error saving refresh token '{token}': {e}")
                raise

    async def get_refresh_token(self, token: str):
        async with self.pool.acquire() as conn:
            token_data = await conn.fetchrow("SELECT * FROM refresh_tokens WHERE token = $1", token)
            logger.info(f"Fetched refresh token '{token}': {'Found' if token_data else 'Not Found'}")
            return dict(token_data) if token_data else None

    async def delete_refresh_token(self, token: str):
        async with self.pool.acquire() as conn:
            try:
                await conn.execute("DELETE FROM refresh_tokens WHERE token = $1", token)
                logger.info(f"Deleted refresh token '{token}'")
            except Exception as e:
                logger.error(f"Error deleting refresh token '{token}': {e}")
                raise

    # Role and Permission methods
    async def create_role(self, role_name: str):
        async with self.pool.acquire() as conn:
            try:
                await conn.execute("""
                    INSERT INTO Roles(role_name)
                    VALUES ($1)
                """, role_name)
                logger.info(f"Created role '{role_name}'")
            except asyncpg.exceptions.UniqueViolationError:
                logger.warning(f"Role '{role_name}' already exists")
            except Exception as e:
                logger.error(f"Error creating role '{role_name}': {e}")
                raise

    async def create_permission(self, permission_name: str):
        async with self.pool.acquire() as conn:
            try:
                await conn.execute("""
                    INSERT INTO Permissions(permission_name)
                    VALUES ($1)
                """, permission_name)
                logger.info(f"Created permission '{permission_name}'")
            except asyncpg.exceptions.UniqueViolationError:
                logger.warning(f"Permission '{permission_name}' already exists")
            except Exception as e:
                logger.error(f"Error creating permission '{permission_name}': {e}")
                raise

    async def get_role_by_name(self, role_name: str):
        async with self.pool.acquire() as conn:
            role = await conn.fetchrow("SELECT * FROM Roles WHERE role_name = $1", role_name)
            logger.info(f"Fetched role '{role_name}': {'Found' if role else 'Not Found'}")
            return dict(role) if role else None

    async def get_permission_by_name(self, permission_name: str):
        async with self.pool.acquire() as conn:
            permission = await conn.fetchrow("SELECT * FROM Permissions WHERE permission_name = $1", permission_name)
            logger.info(f"Fetched permission '{permission_name}': {'Found' if permission else 'Not Found'}")
            return dict(permission) if permission else None

    async def assign_permission_to_role(self, role_id: int, permission_id: int):
        async with self.pool.acquire() as conn:
            try:
                await conn.execute("""
                    INSERT INTO RolePermissions(role_id, permission_id)
                    VALUES ($1, $2)
                    ON CONFLICT DO NOTHING
                """, role_id, permission_id)
                logger.info(f"Assigned permission ID '{permission_id}' to role ID '{role_id}'")
            except Exception as e:
                logger.error(f"Error assigning permission ID '{permission_id}' to role ID '{role_id}': {e}")
                raise

    async def assign_role_to_user(self, user_id: int, role_id: int):
        async with self.pool.acquire() as conn:
            try:
                await conn.execute("""
                    INSERT INTO UserRoles(user_id, role_id)
                    VALUES ($1, $2)
                    ON CONFLICT DO NOTHING
                """, user_id, role_id)
                logger.info(f"Assigned role ID '{role_id}' to user ID '{user_id}'")
            except Exception as e:
                logger.error(f"Error assigning role ID '{role_id}' to user ID '{user_id}': {e}")
                raise

    async def get_user_permissions(self, user_id: int):
        async with self.pool.acquire() as conn:
            permissions = await conn.fetch("""
                SELECT P.permission_name
                FROM Permissions P
                INNER JOIN RolePermissions RP ON P.id = RP.permission_id
                INNER JOIN UserRoles UR ON RP.role_id = UR.role_id
                WHERE UR.user_id = $1
            """, user_id)
            permission_names = [perm['permission_name'] for perm in permissions]
            logger.info(f"Retrieved permissions for user ID '{user_id}': {permission_names}")
            return permission_names
