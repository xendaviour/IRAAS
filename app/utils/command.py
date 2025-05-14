"""
Command-line utility functions for initializing and managing the application.
"""
import logging
from app import create_app, db
from app.utils.template_generator import create_all_templates

logger = logging.getLogger(__name__)

def initialize_templates():
    """Initialize the default incident response templates."""
    app = create_app()
    with app.app_context():
        logger.info("Creating default incident response templates...")
        templates = create_all_templates()
        logger.info(f"Created {len(templates)} templates")
        return templates

if __name__ == "__main__":
    initialize_templates()