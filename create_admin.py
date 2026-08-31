from getpass import getpass

from werkzeug.security import generate_password_hash

from app import create_app
from app.models import db, User, Role


app = create_app()

with app.app_context():

    username = input("Enter admin username: ")
    email = input("Enter admin email: ")
    password = getpass("Enter admin password: ")

    admin_role = Role.query.filter_by(name="Admin").first()

    if not admin_role:
        print("Admin role not found. Please run seed.py first.")
    else:
        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            print("Username already exists.")
        else:
            new_admin = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                role=admin_role
            )

            db.session.add(new_admin)
            db.session.commit()

            print("Admin user created successfully!")