from getpass import getpass
from werkzeug.security import generate_password_hash

from app import create_app
from app.models import db, User, Role


app = create_app()

with app.app_context():

    username = input("Enter employee username: ")
    email = input("Enter employee email: ")
    password = getpass("Enter employee password: ")

    employee_role = Role.query.filter_by(name="Employee").first()

    if not employee_role:
        print("Employee role not found. Please run seed.py first.")
    else:
        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            print("Username already exists.")
        else:
            new_employee = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                role=employee_role
            )

            db.session.add(new_employee)
            db.session.commit()

            print("Employee user created successfully!")