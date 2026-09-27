import os

import pymysql
import psycopg2
from dotenv import load_dotenv


load_dotenv()


# ============================================================
# CONNECT TO AIVEN MYSQL
# ============================================================

print("Connecting to Aiven MySQL...")

mysql_conn = pymysql.connect(
    host=os.getenv("DB_HOST"),
    port=int(os.getenv("DB_PORT", 3306)),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    database=os.getenv("DB_NAME"),
    ssl={}
)

mysql_cursor = mysql_conn.cursor(pymysql.cursors.DictCursor)

print("Aiven connection successful.")


# ============================================================
# CONNECT TO NEON POSTGRESQL
# ============================================================

print("Connecting to Neon PostgreSQL...")

postgres_conn = psycopg2.connect(
    os.getenv("NEON_DATABASE_URL")
)

postgres_cursor = postgres_conn.cursor()

print("Neon connection successful.")


# ============================================================
# TABLE MIGRATION FUNCTION
# ============================================================

def migrate_table(table_name, columns):
    print(f"\nMigrating {table_name}...")

    column_list = ", ".join(columns)
    placeholders = ", ".join(["%s"] * len(columns))

    mysql_cursor.execute(
        f"SELECT {column_list} FROM {table_name}"
    )

    rows = mysql_cursor.fetchall()

    if not rows:
        print(f"{table_name}: 0 records")
        return 0

    # Clear Neon table first.
    # Neon was newly created, so this only removes previously
    # migrated test data if the script is run again.
    postgres_cursor.execute(
        f"TRUNCATE TABLE {table_name} RESTART IDENTITY CASCADE"
    )

    insert_query = f"""
        INSERT INTO {table_name} ({column_list})
        VALUES ({placeholders})
    """

    values = [
        tuple(row[column] for column in columns)
        for row in rows
    ]

    postgres_cursor.executemany(insert_query, values)

    print(f"{table_name}: {len(rows)} records migrated.")

    return len(rows)


# ============================================================
# START MIGRATION
# ============================================================

try:

    print("\n========================================")
    print("      ACCESSIQ DATABASE MIGRATION")
    print("      AIVEN MYSQL -> NEON POSTGRES")
    print("========================================")

    # --------------------------------------------------------
    # 1. ROLES
    # --------------------------------------------------------

    roles_count = migrate_table(
        "roles",
        [
            "id",
            "name",
            "description"
        ]
    )

    # --------------------------------------------------------
    # 2. PERMISSIONS
    # --------------------------------------------------------

    permissions_count = migrate_table(
        "permissions",
        [
            "id",
            "name",
            "description"
        ]
    )

    # --------------------------------------------------------
    # 3. USERS
    # --------------------------------------------------------

    users_count = migrate_table(
        "users",
        [
            "id",
            "username",
            "email",
            "password_hash",
            "department",
            "designation",
            "status",
            "role_id"
        ]
    )

    # --------------------------------------------------------
    # 4. ROLE-PERMISSIONS
    # --------------------------------------------------------

    role_permissions_count = migrate_table(
        "role_permissions",
        [
            "role_id",
            "permission_id"
        ]
    )

    # --------------------------------------------------------
    # 5. AUDIT LOGS
    # --------------------------------------------------------

    audit_logs_count = migrate_table(
        "audit_logs",
        [
            "id",
            "user_id",
            "action",
            "details",
            "timestamp"
        ]
    )

    # --------------------------------------------------------
    # 6. PERMISSION REQUESTS
    # --------------------------------------------------------

    permission_requests_count = migrate_table(
        "permission_requests",
        [
            "id",
            "user_id",
            "permission_id",
            "reason",
            "status",
            "requested_at",
            "reviewed_at",
            "reviewed_by"
        ]
    )

    # ========================================================
    # RESET POSTGRESQL ID SEQUENCES
    # ========================================================

    print("\nResetting PostgreSQL ID sequences...")

    sequence_updates = [
        ("roles", "id"),
        ("permissions", "id"),
        ("users", "id"),
        ("audit_logs", "id"),
        ("permission_requests", "id"),
    ]

    for table, column in sequence_updates:
        postgres_cursor.execute(
            f"""
            SELECT setval(
                pg_get_serial_sequence('{table}', '{column}'),
                COALESCE(
                    (SELECT MAX({column}) FROM {table}),
                    1
                ),
                (SELECT COUNT(*) > 0 FROM {table})
            )
            """
        )

    # ========================================================
    # COMMIT
    # ========================================================

    postgres_conn.commit()

    print("\n========================================")
    print("       MIGRATION COMPLETED")
    print("========================================")

    print(f"roles:                {roles_count}")
    print(f"permissions:          {permissions_count}")
    print(f"users:                {users_count}")
    print(f"role_permissions:     {role_permissions_count}")
    print(f"audit_logs:           {audit_logs_count}")
    print(f"permission_requests:  {permission_requests_count}")

    print("\nAiven database was NOT modified.")
    print("Neon migration committed successfully.")


except Exception as error:

    print("\n========================================")
    print("       MIGRATION FAILED")
    print("========================================")

    print("Error:", error)

    print("\nRolling back Neon changes...")

    postgres_conn.rollback()

    print("Neon rollback completed.")
    print("Aiven database was NOT modified.")


finally:

    mysql_cursor.close()
    mysql_conn.close()

    postgres_cursor.close()
    postgres_conn.close()

    print("\nDatabase connections closed.")