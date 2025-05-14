"""
Entry point for the Incident Response Tool application.
"""
import os
import logging
from app import create_app

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create Flask app
app = create_app()

if __name__ == '__main__':
    # Run the application
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
    logger.info(f"Application running at http://0.0.0.0:{port}/")
