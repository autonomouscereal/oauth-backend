# db_helper.py

import asyncpg
from datetime import datetime
from credential_manager import CredentialManager

class DBHelper:
    def __init__(self):
        self.credentials = CredentialManager.get_db_credentials()

    async def init_db(self):
        await self.connect_create_if_not_exists(
            user=self.credentials['user'],
            database=self.credentials['database'],
            password=self.credentials['password'],
            port=self.credentials['port'],
            host=self.credentials['host']
        )

        conn = await self.get_db_connection()

        # Create tables
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR UNIQUE NOT NULL,
            hashed_password VARCHAR NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        """)

        await conn.execute("""
        CREATE TABLE IF NOT EXISTS oauth2_clients (
            client_id VARCHAR PRIMARY KEY,
            client_secret VARCHAR,
            redirect_uris TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        """)

        await conn.execute("""
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
        """)

        await conn.execute("""
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            token VARCHAR PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            expires_at TIMESTAMPTZ
        );
        """)

        await conn.execute("COMMIT;")
        await conn.close()

    @staticmethod
    async def connect_create_if_not_exists(user, database, password, port, host):
        try:
            conn = await asyncpg.connect(user=user, database=database, password=password, port=port, host=host)
            await conn.close()
        except Exception:
            sys_conn = await asyncpg.connect(user=user, database='postgres', password=password, port=port, host=host)
            await sys_conn.execute(f'CREATE DATABASE "{database}" OWNER "{user}"')
            await sys_conn.close()

    async def get_db_connection(self):
        return await asyncpg.connect(
            user=self.credentials['user'],
            database=self.credentials['database'],
            password=self.credentials['password'],
            port=self.credentials['port'],
            host=self.credentials['host']
        )

    # User methods
    async def add_user(self, email: str, hashed_password: str):
        conn = await self.get_db_connection()
        await conn.execute("""
        INSERT INTO users (email, hashed_password) VALUES ($1, $2)
        """, email, hashed_password)
        await conn.close()

    async def get_user_by_email(self, email: str):
        conn = await self.get_db_connection()
        user = await conn.fetchrow("SELECT * FROM users WHERE email = $1", email)
        await conn.close()
        return dict(user) if user else None

    async def get_user_by_id(self, user_id: int):
        conn = await self.get_db_connection()
        user = await conn.fetchrow("SELECT * FROM users WHERE id = $1", user_id)
        await conn.close()
        return dict(user) if user else None

    # Client methods
    async def get_client_by_id(self, client_id: str):
        conn = await self.get_db_connection()
        client = await conn.fetchrow("SELECT * FROM oauth2_clients WHERE client_id = $1", client_id)
        await conn.close()
        return dict(client) if client else None

    async def add_client(self, client_id, client_secret, redirect_uris):
        conn = await self.get_db_connection()
        await conn.execute('''
            INSERT INTO oauth2_clients (client_id, client_secret, redirect_uris)
            VALUES ($1, $2, $3)
        ''', client_id, client_secret, redirect_uris)

    # Authorization code methods
    async def save_authorization_code(self, auth_code):
        conn = await self.get_db_connection()
        await conn.execute("""
        INSERT INTO oauth2_authorization_codes (
            code, client_id, redirect_uri, scope, user_id, code_challenge, code_challenge_method, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        """, auth_code.code, auth_code.client_id, auth_code.redirect_uri, auth_code.scope,
            auth_code.user_id, auth_code.code_challenge, auth_code.code_challenge_method, auth_code.expires_at)
        await conn.close()

    async def get_authorization_code(self, code: str):
        conn = await self.get_db_connection()
        auth_code = await conn.fetchrow("SELECT * FROM oauth2_authorization_codes WHERE code = $1", code)
        await conn.close()
        return dict(auth_code) if auth_code else None

    async def delete_authorization_code(self, code: str):
        conn = await self.get_db_connection()
        await conn.execute("DELETE FROM oauth2_authorization_codes WHERE code = $1", code)
        await conn.close()

    # Refresh token methods
    async def save_refresh_token(self, user_id: int, token: str, expires_at):
        conn = await self.get_db_connection()
        await conn.execute("""
        INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)
        """, token, user_id, expires_at)
        await conn.close()

    async def get_refresh_token(self, token: str):
        conn = await self.get_db_connection()
        token_data = await conn.fetchrow("SELECT * FROM refresh_tokens WHERE token = $1", token)
        await conn.close()
        return dict(token_data) if token_data else None

    async def delete_refresh_token(self, token: str):
        conn = await self.get_db_connection()
        await conn.execute("DELETE FROM refresh_tokens WHERE token = $1", token)
        await conn.close()


    # Method to create a role
    async def create_role(self, role_name: str):
        conn = await self.get_db_connection()
        try:
            await conn.execute("""
                INSERT INTO public.Roles(role_name)
                VALUES ($1)
            """, role_name)
        finally:
            await conn.close()

    # Method to create a permission
    async def create_permission(self, permission_name: str):
        conn = await self.get_db_connection()
        try:
            await conn.execute("""
                INSERT INTO public.Permissions(permission_name)
                VALUES ($1)
            """, permission_name)
        finally:
            await conn.close()

    # Method to get a role by name
    async def get_role_by_name(self, role_name: str):
        conn = await self.get_db_connection()
        try:
            role = await conn.fetchrow("SELECT * FROM public.Roles WHERE role_name = $1", role_name)
            return role
        finally:
            await conn.close()

    # Method to get a permission by name
    async def get_permission_by_name(self, permission_name: str):
        conn = await self.get_db_connection()
        try:
            permission = await conn.fetchrow("SELECT * FROM public.Permissions WHERE permission_name = $1", permission_name)
            return permission
        finally:
            await conn.close()

    # Method to assign a permission to a role
    async def assign_permission_to_role(self, role_id: int, permission_id: int):
        conn = await self.get_db_connection()
        try:
            await conn.execute("""
                INSERT INTO public.RolePermissions(role_id, permission_id)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
            """, role_id, permission_id)
        finally:
            await conn.close()

    # Method to assign a role to a user
    async def assign_role_to_user(self, user_id: int, role_id: int):
        conn = await self.get_db_connection()
        try:
            await conn.execute("""
                INSERT INTO public.UserRoles(user_id, role_id)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
            """, user_id, role_id)
        finally:
            await conn.close()

    # Method to get permissions for a user
    async def get_user_permissions(self, user_id: int):
        conn = await self.get_db_connection()
        try:
            permissions = await conn.fetch("""
                SELECT P.permission_name
                FROM public.Permissions P
                INNER JOIN public.RolePermissions RP ON P.id = RP.permission_id
                INNER JOIN public.UserRoles UR ON RP.role_id = UR.role_id
                WHERE UR.user_id = $1
            """, user_id)
            return [perm['permission_name'] for perm in permissions]
        finally:
            await conn.close()

    # Method to save a refresh token
    async def save_refresh_token(self, user_id: int, refresh_token: str, expires_at):
        conn = await self.get_db_connection()
        try:
            await conn.execute("""
                INSERT INTO public.RefreshTokens(user_id, token, expires_at)
                VALUES ($1, $2, $3)
            """, user_id, refresh_token, expires_at)
        finally:
            await conn.close()

    # Method to get a refresh token
    async def get_refresh_token(self, refresh_token: str):
        conn = await self.get_db_connection()
        try:
            token_data = await conn.fetchrow("""
                SELECT * FROM public.RefreshTokens WHERE token = $1
            """, refresh_token)
            return token_data
        finally:
            await conn.close()

    # Method to revoke a refresh token
    async def revoke_refresh_token(self, refresh_token: str):
        conn = await self.get_db_connection()
        try:
            await conn.execute("""
                DELETE FROM public.RefreshTokens WHERE token = $1
            """, refresh_token)
        finally:
            await conn.close()