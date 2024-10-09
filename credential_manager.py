# credential_manager.py
import os


class CredentialManager:
    @staticmethod
    def get_db_credentials():
        required_vars = ['db_username', 'db_password']
        missing_vars = [var for var in required_vars if os.getenv(var) is None]
        if missing_vars:
            raise EnvironmentError(f"Missing required environment variables: {', '.join(missing_vars)}")
        return {
            'user': os.environ.get('db_username'),
            'password': os.environ.get('db_password'),
            'database': os.getenv('OAUTHDB', 'OAUTHDB'),
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': int(os.getenv('DB_PORT', 5999))
        }
    
    @staticmethod
    def get_secret_key():
        secret_key = os.getenv('SECRET_KEY', 'reallysecretkey')
        if not secret_key:
            raise EnvironmentError("Missing required environment variable: SECRET_KEY")
        return secret_key
