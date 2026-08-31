from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()



# Association table between roles and permissions
role_permissions = db.Table(
    "role_permissions",
    db.Column(
        "role_id",
        db.Integer,
        db.ForeignKey("roles.id"),
        primary_key=True
    ),
    db.Column(
        "permission_id",
        db.Integer,
        db.ForeignKey("permissions.id"),
        primary_key=True
    )
)


class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255))

    permissions = db.relationship(
        "Permission",
        secondary=role_permissions,
        backref="roles"
    )


class Permission(db.Model):
    __tablename__ = "permissions"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(255))


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    department = db.Column(
        db.String(100),
        nullable=False,
        default="Not Assigned"
    )

    designation = db.Column(
        db.String(100),
        nullable=False,
        default="Not Assigned"
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="Active"
    )

    role_id = db.Column(
        db.Integer,
        db.ForeignKey("roles.id"),
        nullable=False
    )

    role = db.relationship("Role", backref="users")

class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True
    )
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp()
    )

    user = db.relationship(
        "User",
        backref="audit_logs"
    )
class PermissionRequest(db.Model):
    __tablename__ = "permission_requests"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    permission_id = db.Column(
        db.Integer,
        db.ForeignKey("permissions.id"),
        nullable=False
    )

    reason = db.Column(
        db.String(255),
        nullable=True
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="Pending"
    )

    requested_at = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp()
    )

    reviewed_at = db.Column(
        db.DateTime,
        nullable=True
    )

    reviewed_by = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True
    )

    user = db.relationship(
        "User",
        foreign_keys=[user_id],
        backref="permission_requests"
    )

    permission = db.relationship(
        "Permission",
        backref="permission_requests"
    )

    reviewer = db.relationship(
        "User",
        foreign_keys=[reviewed_by]
    )