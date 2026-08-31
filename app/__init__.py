import os

from flask import Flask
from dotenv import load_dotenv
from sqlalchemy import URL

from .models import db
from .routes import main

load_dotenv()


def create_app():
    app = Flask(__name__)
    app.secret_key = os.getenv("SECRET_KEY")

    database_url = URL.create(
        drivername="mysql+pymysql",
        username=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT", 3306)),
        database=os.getenv("DB_NAME")
    )

    
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)


    app.register_blueprint(main)

    with app.app_context():
     db.create_all()

   

    return app