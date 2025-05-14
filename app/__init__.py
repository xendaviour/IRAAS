import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_login import LoginManager
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_jwt_extended import JWTManager

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Define database base class
class Base(DeclarativeBase):
    pass

# Initialize extensions
db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()
jwt = JWTManager()

def create_app():
    # Create Flask app
    app = Flask(__name__)
    
    # Load config
    from app.config import Config
    app.config.from_object(Config)
    
    # Set secret key
    app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")

    # Configure ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    
    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'
    jwt.init_app(app)
    
    # Register blueprints
    from app.routes import main_bp
    from app.auth import auth_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    
    # Create database tables if they don't exist with retry logic
    with app.app_context():
        try:
            from app import models
            db.create_all()
            logger.info("Database tables created or confirmed to exist")
            
            # Initialize default incident response templates
            try:
                from app.utils.template_generator import create_all_templates
                templates = create_all_templates()
                logger.info(f"Initialized {len(templates)} incident response templates")
            except Exception as template_err:
                logger.error(f"Template initialization error: {str(template_err)}")
                
        except Exception as e:
            logger.error(f"Database initialization error: {str(e)}")
            logger.info("Attempting to reconnect to database...")
            
            import time
            # Wait a moment and try again
            time.sleep(2)
            try:
                db.create_all()
                logger.info("Database reconnection successful")
            except Exception as e2:
                logger.error(f"Database reconnection failed: {str(e2)}")
                logger.warning("Application may experience database connectivity issues")
    
    return app
