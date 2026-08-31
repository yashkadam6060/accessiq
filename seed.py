from app import create_app
from app.models import db, Role, Permission


app = create_app()

with app.app_context():

    # Create roles
    admin = Role(
        name="Admin",
        description="Full system access"
    )

    manager = Role(
        name="Manager",
        description="Manage users and view reports"
    )

    employee = Role(
        name="Employee",
        description="Basic system access"
    )

    # Create permissions
    view_users = Permission(
        name="View Users",
        description="View user information"
    )

    create_user = Permission(
        name="Create User",
        description="Create new users"
    )

    delete_user = Permission(
        name="Delete User",
        description="Delete users"
    )

    manage_roles = Permission(
        name="Manage Roles",
        description="Create and manage roles"
    )

    view_reports = Permission(
        name="View Reports",
        description="View system reports"
    )

    view_profile = Permission(
        name="View Profile",
        description="View own profile"
    )

    # Add everything to database
    db.session.add_all([
        admin,
        manager,
        employee,
        view_users,
        create_user,
        delete_user,
        manage_roles,
        view_reports,
        view_profile
    ])

    db.session.commit()

    # Assign permissions to roles
    admin.permissions.extend([
        view_users,
        create_user,
        delete_user,
        manage_roles,
        view_reports,
        view_profile
    ])

    manager.permissions.extend([
        view_users,
        view_reports,
        view_profile
    ])

    employee.permissions.extend([
        view_profile
    ])

    db.session.commit()

    print("Roles and permissions created successfully!")