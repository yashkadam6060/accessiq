import os

from flask import Flask
from dotenv import load_dotenv

from .models import db
from .routes import main

load_dotenv()


def create_app():
    app = Flask(__name__)

    # Secret key
    app.secret_key = os.getenv("SECRET_KEY")

    # Database URL
    database_url = os.getenv("NEON_DATABASE_URL")

    # Database configuration
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Initialize database
    db.init_app(app)

    # Register routes
    app.register_blueprint(main)

    # Create tables
    with app.app_context():
        db.create_all()

    return app