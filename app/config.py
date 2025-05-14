import os

class Config:
    """Application configuration class"""
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/incident_response')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,  # Enable connection testing before executing queries
        'pool_recycle': 300,    # Recycle connections after 5 minutes
        'connect_args': {
            'connect_timeout': 10,  # Connection timeout in seconds
            'application_name': 'incident_response_tool'  # Identify app in database logs
        }
    }
    
    # JWT configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'dev-jwt-secret')
    JWT_ACCESS_TOKEN_EXPIRES = 86400  # 24 hours
    
    # Application configuration
    SECRET_KEY = os.environ.get('SESSION_SECRET', 'dev-secret-key')
    DEBUG = os.environ.get('DEBUG', 'True').lower() == 'true'
    
    # Host and Port configuration
    HOST = '0.0.0.0'
    PORT = 5000
