from datetime import datetime, timedelta

from flask import Blueprint, render_template, request, redirect, url_for, session
from werkzeug.security import check_password_hash, generate_password_hash

from .models import User, Role, Permission, AuditLog, db, PermissionRequest
from .ai.analyzer import analyze_activity


main = Blueprint("main", __name__)


def log_activity(user_id, action, details=None):

    log = AuditLog(
        user_id=user_id,
        action=action,
        details=details
    )

    db.session.add(log)
    db.session.commit()


def has_permission(permission_name):

    if "user_id" not in session:
        return False

    user = User.query.get(session["user_id"])

    if not user or not user.role:
        return False

    return any(
        permission.name == permission_name
        for permission in user.role.permissions
    )


@main.route("/")
def home():

    return redirect(url_for("main.login"))


@main.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(
            username=username
        ).first()

        if user and check_password_hash(
            user.password_hash,
            password
        ):

            # Check whether the account is active

            if user.status != "Active":

                log_activity(
                    user.id,
                    "INACTIVE_LOGIN_ATTEMPT",
                    "Inactive user attempted to log in"
                )

                return render_template(
                    "login.html",
                    error="Your account is inactive. Please contact an administrator."
                )

            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role.name

            log_activity(
                user.id,
                "LOGIN",
                "Successful login"
            )

            return redirect(
                url_for("main.dashboard")
            )

        # Record failed login

        if user:

            log_activity(
                user.id,
                "FAILED_LOGIN",
                "Incorrect password"
            )

        else:

            log_activity(
                None,
                "FAILED_LOGIN",
                f"Unknown username: {username}"
            )

        return render_template(
            "login.html",
            error="Invalid username or password."
        )

    return render_template("login.html")


@main.route("/dashboard")
def dashboard():

    if "user_id" not in session:

        return redirect(
            url_for("main.login")
        )

    # --------------------------------
    # Dashboard statistics
    # --------------------------------

    total_users = User.query.count()

    total_roles = Role.query.count()

    pending_requests = PermissionRequest.query.filter_by(
        status="Pending"
    ).count()

    total_events = AuditLog.query.count()

    failed_logins = AuditLog.query.filter_by(
        action="FAILED_LOGIN"
    ).count()

    access_denied = AuditLog.query.filter_by(
        action="ACCESS_DENIED"
    ).count()


    # --------------------------------
    # Notifications
    # --------------------------------

    notifications = []

    current_user_id = session["user_id"]
    current_role = session["role"]

    if current_role == "Admin":

        # Pending permission requests
        pending_notification_requests = (
            PermissionRequest.query
            .filter_by(status="Pending")
            .order_by(
                PermissionRequest.requested_at.desc()
            )
            .limit(5)
            .all()
        )

        for permission_request in pending_notification_requests:

            notifications.append({
                "type": "warning",
                "icon": "bi-key-fill",
                "title": "New Permission Request",
                "message": (
                    f"{permission_request.user.username} "
                    f"requested {permission_request.permission.name}."
                ),
                "timestamp": (
                    permission_request.requested_at.strftime(
                        "%d %b %Y, %I:%M %p"
                    )
                    if permission_request.requested_at
                    else "Recently"
                )
            })


        # Recent failed logins
        recent_failed_logins = (
            AuditLog.query
            .filter_by(action="FAILED_LOGIN")
            .order_by(
                AuditLog.timestamp.desc()
            )
            .limit(5)
            .all()
        )

        for log in recent_failed_logins:

            notifications.append({
                "type": "danger",
                "icon": "bi-shield-exclamation",
                "title": "Failed Login Attempt",
                "message": log.details or "Failed login attempt detected.",
                "timestamp": (
                    log.timestamp.strftime(
                        "%d %b %Y, %I:%M %p"
                    )
                    if log.timestamp
                    else "Recently"
                )
            })


        # Recent unauthorized access attempts
        recent_access_denied = (
            AuditLog.query
            .filter_by(action="ACCESS_DENIED")
            .order_by(
                AuditLog.timestamp.desc()
            )
            .limit(5)
            .all()
        )

        for log in recent_access_denied:

            notifications.append({
                "type": "danger",
                "icon": "bi-lock-fill",
                "title": "Access Denied",
                "message": log.details or "Unauthorized access attempt detected.",
                "timestamp": (
                    log.timestamp.strftime(
                        "%d %b %Y, %I:%M %p"
                    )
                    if log.timestamp
                    else "Recently"
                )
            })

    else:

        # Employee permission request notifications
        user_requests = (
            PermissionRequest.query
            .filter_by(
                user_id=current_user_id
            )
            .filter(
                PermissionRequest.status.in_(
                    ["Approved", "Rejected"]
                )
            )
            .order_by(
                PermissionRequest.reviewed_at.desc()
            )
            .limit(5)
            .all()
        )

        for permission_request in user_requests:

            if permission_request.status == "Approved":

                notifications.append({
                    "type": "success",
                    "icon": "bi-check-circle-fill",
                    "title": "Permission Approved",
                    "message": (
                        f"Your request for "
                        f"{permission_request.permission.name} "
                        f"was approved."
                    ),
                    "timestamp": (
                        permission_request.reviewed_at.strftime(
                            "%d %b %Y, %I:%M %p"
                        )
                        if permission_request.reviewed_at
                        else "Recently"
                    )
                })

            elif permission_request.status == "Rejected":

                notifications.append({
                    "type": "danger",
                    "icon": "bi-x-circle-fill",
                    "title": "Permission Rejected",
                    "message": (
                        f"Your request for "
                        f"{permission_request.permission.name} "
                        f"was rejected."
                    ),
                    "timestamp": (
                        permission_request.reviewed_at.strftime(
                            "%d %b %Y, %I:%M %p"
                        )
                        if permission_request.reviewed_at
                        else "Recently"
                    )
                })


    # Sort notifications by timestamp text is not reliable,
    # so simply limit the displayed notifications.
    notifications = notifications[:10]

    notification_count = len(notifications)


    # --------------------------------
    # AI Security Analysis
    # --------------------------------

    logs = AuditLog.query.order_by(
        AuditLog.timestamp.desc()
    ).all()

    analysis = analyze_activity(logs)


    # --------------------------------
    # Role distribution
    # --------------------------------

    role_data = {}

    for role in Role.query.all():

        role_data[role.name] = User.query.filter_by(
            role_id=role.id
        ).count()


    # --------------------------------
    # Security activity chart
    # --------------------------------

    chart_labels = []

    successful_logins_data = []

    security_events_data = []


    today = datetime.now().date()


    for i in range(6, -1, -1):

        current_date = today - timedelta(days=i)

        next_date = current_date + timedelta(days=1)


        successful_logins = AuditLog.query.filter(
            AuditLog.action == "LOGIN",
            AuditLog.timestamp >= current_date,
            AuditLog.timestamp < next_date
        ).count()


        security_events = AuditLog.query.filter(
            AuditLog.action.in_(
                [
                    "FAILED_LOGIN",
                    "ACCESS_DENIED"
                ]
            ),
            AuditLog.timestamp >= current_date,
            AuditLog.timestamp < next_date
        ).count()


        chart_labels.append(
            current_date.strftime("%a")
        )

        successful_logins_data.append(
            successful_logins
        )

        security_events_data.append(
            security_events
        )


    # --------------------------------
    # Render Dashboard
    # --------------------------------

    return render_template(

        "dashboard.html",

        username=session["username"],

        role=session["role"],

        pending_requests=pending_requests,

        total_users=total_users,

        total_roles=total_roles,

        total_events=total_events,

        failed_logins=failed_logins,

        access_denied=access_denied,

        chart_labels=chart_labels,

        successful_logins_data=successful_logins_data,

        security_events_data=security_events_data,

        role_data=role_data,

        analysis=analysis,

        notifications=notifications,

        notification_count=notification_count
    )


@main.route("/audit-logs")
def audit_logs():

    if "user_id" not in session:

        return redirect(
            url_for("main.login")
        )

    if session.get("role") != "Admin":

        return "Access Denied: Admins only.", 403

    logs = AuditLog.query.order_by(
        AuditLog.timestamp.desc()
    ).all()

    return render_template(
        "audit_logs.html",
        logs=logs
    )


@main.route("/logout")
def logout():

    user_id = session.get("user_id")

    if user_id:

        log_activity(
            user_id,
            "LOGOUT",
            "User logged out"
        )

    session.clear()

    return redirect(
        url_for("main.login")
    )


@main.route("/admin")
def admin():

    if "user_id" not in session:

        return redirect(
            url_for("main.login")
        )

    if session.get("role") != "Admin":

        return "Access Denied: Admins only", 403

    search = request.args.get(
        "search",
        ""
    ).strip()

    department = request.args.get(
        "department",
        ""
    ).strip()

    role_id = request.args.get(
        "role_id",
        ""
    ).strip()

    status = request.args.get(
        "status",
        ""
    ).strip()


    query = User.query


    if search:

        query = query.filter(

            (User.username.ilike(
                f"%{search}%"
            ))

            |

            (User.email.ilike(
                f"%{search}%"
            ))

        )


    if department:

        query = query.filter(
            User.department == department
        )


    if role_id:

        query = query.filter(
            User.role_id == role_id
        )


    if status:

        query = query.filter(
            User.status == status
        )


    users = query.all()


    departments = db.session.query(
        User.department
    ).distinct().all()


    departments = [

        department[0]

        for department in departments

        if department[0]

    ]


    roles = Role.query.all()


    return render_template(

        "admin.html",

        users=users,

        departments=departments,

        roles=roles,

        search=search,

        selected_department=department,

        selected_role=role_id,

        selected_status=status

    )


@main.route(
    "/admin/add-user",
    methods=["GET", "POST"]
)
def add_user():

    if "user_id" not in session:

        return redirect(
            url_for("main.login")
        )

    if session.get("role") != "Admin":

        return "Access Denied: Admins only", 403


    roles = Role.query.all()


    if request.method == "POST":

        username = request.form.get(
            "username"
        )

        email = request.form.get(
            "email"
        )

        password = request.form.get(
            "password"
        )

        department = request.form.get(
            "department"
        )

        designation = request.form.get(
            "designation"
        )

        role_id = request.form.get(
            "role_id"
        )

        status = request.form.get(
            "status"
        )


        existing_user = User.query.filter(

            (User.username == username)

            |

            (User.email == email)

        ).first()


        if existing_user:

            return render_template(

                "add_user.html",

                roles=roles,

                error="Username or email already exists."

            )


        new_user = User(

            username=username,

            email=email,

            password_hash=generate_password_hash(
                password
            ),

            department=department,

            designation=designation,

            role_id=role_id,

            status=status

        )


        db.session.add(new_user)

        db.session.commit()


        log_activity(

            session["user_id"],

            "USER_CREATED",

            f"Created user: {username}"

        )


        return redirect(
            url_for("main.admin")
        )


    return render_template(

        "add_user.html",

        roles=roles

    )


@main.route(
    "/admin/edit-user/<int:user_id>",
    methods=["GET", "POST"]
)
def edit_user(user_id):

    if "user_id" not in session:

        return redirect(
            url_for("main.login")
        )

    if session.get("role") != "Admin":

        return "Access Denied: Admins only", 403


    user = User.query.get_or_404(
        user_id
    )

    roles = Role.query.all()


    if request.method == "POST":

        user.department = request.form.get(
            "department"
        )

        user.designation = request.form.get(
            "designation"
        )

        user.role_id = request.form.get(
            "role_id"
        )

        user.status = request.form.get(
            "status"
        )


        db.session.commit()


        log_activity(

            session["user_id"],

            "USER_UPDATED",

            f"Updated user: {user.username}"

        )


        return redirect(
            url_for("main.admin")
        )


    return render_template(

        "edit_user.html",

        user=user,

        roles=roles

    )


@main.route("/manage-roles")
def manage_roles():

    if "user_id" not in session:

        return redirect(
            url_for("main.login")
        )


    if not has_permission(
        "Manage Roles"
    ):

        log_activity(

            session["user_id"],

            "ACCESS_DENIED",

            "Attempted to access Role Management"

        )

        return (
            "Access Denied: You do not have permission to manage roles.",
            403
        )


    roles = Role.query.all()


    return render_template(

        "manage_roles.html",

        roles=roles

    )


@main.route(
    "/manage-roles/edit/<int:role_id>",
    methods=["GET", "POST"]
)
def edit_role(role_id):

    if "user_id" not in session:

        return redirect(
            url_for("main.login")
        )


    if not has_permission(
        "Manage Roles"
    ):

        return (
            "Access Denied: You do not have permission to manage roles.",
            403
        )


    role = Role.query.get_or_404(
        role_id
    )

    permissions = Permission.query.all()


    if request.method == "POST":

        selected_permissions = request.form.getlist(
            "permissions"
        )


        role.permissions = (

            Permission.query.filter(
                Permission.id.in_(
                    selected_permissions
                )
            ).all()

            if selected_permissions

            else []

        )


        db.session.commit()


        log_activity(

            session["user_id"],

            "ROLE_PERMISSIONS_UPDATED",

            f"Updated permissions for role: {role.name}"

        )


        return redirect(
            url_for("main.manage_roles")
        )


    return render_template(

        "edit_role.html",

        role=role,

        permissions=permissions

    )


@main.route(
    "/manage-roles/add",
    methods=["GET", "POST"]
)
def add_role():

    if "user_id" not in session:

        return redirect(
            url_for("main.login")
        )


    if not has_permission(
        "Manage Roles"
    ):

        return (
            "Access Denied: You do not have permission to manage roles.",
            403
        )


    permissions = Permission.query.all()


    if request.method == "POST":

        name = request.form.get(
            "name"
        )

        description = request.form.get(
            "description"
        )


        existing_role = Role.query.filter_by(
            name=name
        ).first()


        if existing_role:

            return render_template(

                "add_role.html",

                permissions=permissions,

                error="Role already exists."

            )


        new_role = Role(

            name=name,

            description=description

        )


        db.session.add(new_role)

        db.session.commit()


        log_activity(

            session["user_id"],

            "ROLE_CREATED",

            f"Created role: {name}"

        )


        return redirect(
            url_for("main.manage_roles")
        )


    return render_template(

        "add_role.html",

        permissions=permissions

    )


@main.route("/ai-analysis")
def ai_analysis():

    if "user_id" not in session:

        return redirect(
            url_for("main.login")
        )


    if session.get("role") != "Admin":

        return "Access Denied: Admins only.", 403


    logs = AuditLog.query.order_by(
        AuditLog.timestamp.desc()
    ).all()


    analysis = analyze_activity(
        logs
    )


    return render_template(

        "ai_analysis.html",

        analysis=analysis

    )


@main.route("/permission-requests")
def permission_requests():

    if "user_id" not in session:

        return redirect(
            url_for("main.login")
        )


    permissions = Permission.query.all()


    requests = PermissionRequest.query.filter_by(

        user_id=session["user_id"]

    ).order_by(

        PermissionRequest.requested_at.desc()

    ).all()


    return render_template(

        "permission_requests.html",

        permissions=permissions,

        requests=requests

    )


@main.route(
    "/permission-requests/create",
    methods=["POST"]
)
def create_permission_request():

    if "user_id" not in session:

        return redirect(
            url_for("main.login")
        )


    permission_id = request.form.get(
        "permission_id"
    )

    reason = request.form.get(
        "reason"
    )


    permission = Permission.query.get_or_404(
        permission_id
    )


    existing_request = PermissionRequest.query.filter_by(

        user_id=session["user_id"],

        permission_id=permission.id,

        status="Pending"

    ).first()


    if existing_request:

        return redirect(
            url_for("main.permission_requests")
        )


    new_request = PermissionRequest(

        user_id=session["user_id"],

        permission_id=permission.id,

        reason=reason,

        status="Pending"

    )


    db.session.add(new_request)

    db.session.commit()


    log_activity(

        session["user_id"],

        "PERMISSION_REQUESTED",

        f"Requested permission: {permission.name}"

    )


    return redirect(
        url_for("main.permission_requests")
    )


@main.route(
    "/admin/permission-requests"
)
def admin_permission_requests():

    if "user_id" not in session:

        return redirect(
            url_for("main.login")
        )


    if session.get("role") != "Admin":

        return "Access Denied: Admins only.", 403


    requests = PermissionRequest.query.order_by(

        PermissionRequest.requested_at.desc()

    ).all()


    return render_template(

        "admin_permission_requests.html",

        requests=requests

    )


@main.route(
    "/admin/permission-requests/<int:request_id>/<action>",
    methods=["POST"]
)
def review_permission_request(
    request_id,
    action
):

    if "user_id" not in session:

        return redirect(
            url_for("main.login")
        )


    if session.get("role") != "Admin":

        return "Access Denied: Admins only.", 403


    permission_request = PermissionRequest.query.get_or_404(
        request_id
    )


    if permission_request.status != "Pending":

        return redirect(
            url_for("main.admin_permission_requests")
        )


    if action not in [
        "approve",
        "reject"
    ]:

        return "Invalid action.", 400


    if action == "approve":

        user = permission_request.user

        permission = permission_request.permission


        if permission not in user.role.permissions:

            user.role.permissions.append(
                permission
            )


        permission_request.status = "Approved"


        log_activity(

            session["user_id"],

            "PERMISSION_REQUEST_APPROVED",

            f"Approved permission '{permission.name}' for user: {user.username}"

        )


    else:

        permission_request.status = "Rejected"


        log_activity(

            session["user_id"],

            "PERMISSION_REQUEST_REJECTED",

            f"Rejected permission '{permission_request.permission.name}' for user: {permission_request.user.username}"

        )


    permission_request.reviewed_at = datetime.now()

    permission_request.reviewed_by = session["user_id"]


    db.session.commit()


    return redirect(
        url_for("main.admin_permission_requests")
    )
@main.route("/change-password", methods=["GET", "POST"])
def change_password():

    # Check if user is logged in
    if "user_id" not in session:
        return redirect(
            url_for("main.login")
        )

    # Get current logged-in user
    user = User.query.get(
        session["user_id"]
    )

    if request.method == "POST":

        current_password = request.form.get(
            "current_password"
        )

        new_password = request.form.get(
            "new_password"
        )

        confirm_password = request.form.get(
            "confirm_password"
        )

        # Check current password
        if not check_password_hash(
            user.password_hash,
            current_password
        ):

            return render_template(
                "change_password.html",
                error="Current password is incorrect."
            )

        # Check if new passwords match
        if new_password != confirm_password:

            return render_template(
                "change_password.html",
                error="New passwords do not match."
            )

        # Check minimum password length
        if len(new_password) < 6:

            return render_template(
                "change_password.html",
                error="New password must be at least 6 characters long."
            )

        # Update password securely
        user.password_hash = generate_password_hash(
            new_password
        )

        db.session.commit()

        # Create audit log
        log_activity(
            user.id,
            "PASSWORD_CHANGED",
            "User changed their password"
        )

        return render_template(
            "change_password.html",
            success="Password changed successfully."
        )

    return render_template(
        "change_password.html"
    )
@main.route("/admin/delete-user/<int:user_id>", methods=["POST"])
def delete_user(user_id):

    # Check if user is logged in
    if "user_id" not in session:
        return redirect(url_for("main.login"))

    # Only Admin can delete users
    if session.get("role") != "Admin":
        return "Access Denied: Admins only", 403

    # Prevent admin from deleting their own account
    if user_id == session["user_id"]:
        return "You cannot delete your own account.", 403

    # Find the user
    user = User.query.get_or_404(user_id)

    username = user.username

    # Delete the user
    db.session.delete(user)
    db.session.commit()

    # Add audit log
    log_activity(
        session["user_id"],
        "USER_DELETED",
        f"Deleted user: {username}"
    )

    return redirect(
        url_for("main.admin")
    )