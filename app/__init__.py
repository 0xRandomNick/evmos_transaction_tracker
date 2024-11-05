# app/__init__.py

import logging
from flask import Flask
from dotenv import load_dotenv
import os

def create_app():
    load_dotenv()  # Load environment variables from .env
    app = Flask(__name__)
    
    # Set a secure secret key for session management
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'Replace_With_A_Secure_Key'

    # Configure Logging
    logging.basicConfig(
        level=logging.DEBUG,  # Set to DEBUG to capture all logs
        format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]',
        handlers=[
            logging.FileHandler("app.log"),
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger()

    # Ensure the temporary directory exists
    temp_dir = os.path.join(app.instance_path, 'temp')
    os.makedirs(temp_dir, exist_ok=True)
    app.config['TEMP_DIR'] = temp_dir

    # Import and register blueprints
    from .routes import main
    app.register_blueprint(main)

    return app
