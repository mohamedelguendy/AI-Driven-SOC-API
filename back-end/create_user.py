"""Create a SOC user from the command line.

Run from the back-end folder with the venv active:
    python create_user.py
"""
import getpass
import sys

from psycopg.errors import UniqueViolation

from app.db import pool
from app.security import hash_password

ROLES = ("tier2", "tier3", "admin")


def main() -> None:
    username = input("Username: ").strip()
    role = input(f"Role {ROLES}: ").strip()
    if not username or role not in ROLES:
        sys.exit("Username is required and role must be one of " + ", ".join(ROLES))

    password = getpass.getpass("Password: ")
    if len(password) < 8:
        sys.exit("Password must be at least 8 characters")

    try:
        with pool.connection() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
                (username, hash_password(password), role),
            )
    except UniqueViolation:
        sys.exit(f"User '{username}' already exists")
    finally:
        pool.close()

    print(f"Created {role} user '{username}'")


if __name__ == "__main__":
    main()