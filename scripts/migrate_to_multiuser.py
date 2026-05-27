#!/usr/bin/env python3
"""
Multi-user migration script.

Run: python scripts/migrate_to_multiuser.py

Actions:
1. Add users table
2. Add user_id columns to relevant tables (ALTER TABLE ADD COLUMN)
3. Create default admin user (copy password from .admin_password_hash or generate random)
4. Backfill user_id on all existing rows
5. Create user_configs row for admin
6. Validate row counts
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TABLES_NEEDING_USER_ID = [
    "analysis_history",
    "alert_rules",
    "alert_triggers",
    "backtest_results",
    "backtest_summaries",
    "conversation_messages",
]


def _read_admin_password_hash() -> str | None:
    """Read existing admin password hash from disk."""
    data_dir = os.getenv("DATABASE_PATH", "./data/stock_analysis.db")
    data_dir = Path(data_dir).resolve().parent
    hash_file = data_dir / ".admin_password_hash"
    if not hash_file.exists():
        return None
    try:
        return hash_file.read_text().strip()
    except OSError:
        return None


def _generate_random_password() -> tuple[str, str]:
    """Generate a random password and its hash. Returns (plaintext, hash_string)."""
    plaintext = secrets.token_urlsafe(12)
    import base64

    salt = secrets.token_bytes(32)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        plaintext.encode("utf-8"),
        salt=salt,
        iterations=100_000,
    )
    salt_b64 = base64.standard_b64encode(salt).decode("ascii")
    hash_b64 = base64.standard_b64encode(derived).decode("ascii")
    return plaintext, f"{salt_b64}:{hash_b64}"


def _create_users_table(cursor) -> tuple[dict, bool]:
    """Create users table if not exists. Returns (columns, created)."""
    from src.storage import DatabaseManager

    db = DatabaseManager.get_instance()
    engine = db._engine
    # Use SQLAlchemy metadata to create the table
    Base = db.Base if hasattr(db, "Base") else None
    from src.storage import Base as StorageBase

    StorageBase.metadata.create_all(engine, tables=[StorageBase.metadata.tables.get("users")])
    StorageBase.metadata.create_all(engine, tables=[StorageBase.metadata.tables.get("user_configs")])
    return {}, True


def _add_user_id_columns(cursor) -> int:
    """Add user_id columns to all tables. Returns count of columns added."""
    added = 0
    for table in TABLES_NEEDING_USER_ID:
        try:
            cursor.execute(
                f"ALTER TABLE {table} ADD COLUMN user_id INTEGER REFERENCES users(id)"
            )
            added += 1
        except Exception as exc:
            if "duplicate column" in str(exc).lower() or "already exists" in str(exc).lower():
                pass
            else:
                logger.warning("Failed to add user_id to %s: %s", table, exc)
    return added


def _backfill_user_ids(cursor, connection, admin_id: int) -> dict[str, int]:
    """Backfill user_id = admin_id on all existing rows. Returns table->count map."""
    counts = {}
    for table in TABLES_NEEDING_USER_ID:
        try:
            cursor.execute(
                f"UPDATE {table} SET user_id = ? WHERE user_id IS NULL",
                (admin_id,),
            )
            counts[table] = cursor.rowcount
        except Exception as exc:
            logger.warning("Failed to backfill %s: %s", table, exc)
            counts[table] = -1
    connection.commit()
    return counts


def _ensure_users_table(cursor, connection) -> bool:
    """Create users table via raw SQL if ORM didn't work. Returns True if created."""
    try:
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(64) NOT NULL UNIQUE,
                password_hash VARCHAR(256) NOT NULL,
                display_name VARCHAR(128),
                is_admin BOOLEAN NOT NULL DEFAULT 0,
                is_active BOOLEAN NOT NULL DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )"""
        )
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS user_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE REFERENCES users(id),
                stock_list TEXT,
                preferences_json TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )"""
        )
        connection.commit()
        return True
    except Exception as exc:
        logger.error("Failed to create users/user_configs tables: %s", exc)
        return False


def main() -> int:
    # Setup env before importing anything else
    from src.config import setup_env
    setup_env()

    from src.storage import DatabaseManager

    db = DatabaseManager.get_instance()

    with db.get_session() as session:
        connection = session.connection().connection  # raw sqlite3 connection
        cursor = connection.cursor()

        # Step 1: Create users and user_configs tables
        logger.info("Creating users and user_configs tables...")
        _ensure_users_table(cursor, connection)

        # Step 2: Add user_id columns
        logger.info("Adding user_id columns...")
        added = _add_user_id_columns(cursor)
        connection.commit()
        logger.info("Added %d new user_id columns", added)

        # Step 3: Check if admin user already exists
        cursor.execute("SELECT id FROM users WHERE username = 'admin' LIMIT 1")
        existing_admin = cursor.fetchone()

        if existing_admin:
            admin_id = existing_admin[0]
            logger.info("Admin user already exists (id=%d)", admin_id)
            plaintext_password = None
        else:
            # Try to read existing admin password hash
            existing_hash = _read_admin_password_hash()
            if existing_hash:
                logger.info("Found existing .admin_password_hash, migrating to users table")
                password_hash = existing_hash
                plaintext_password = None
            else:
                plaintext_password, password_hash = _generate_random_password()
                logger.info("No existing password found, generated random password")

            cursor.execute(
                "INSERT INTO users (username, password_hash, display_name, is_admin, is_active) "
                "VALUES (?, ?, ?, 1, 1)",
                ("admin", password_hash, "Administrator"),
            )
            connection.commit()
            admin_id = cursor.lastrowid
            logger.info("Created admin user (id=%d)", admin_id)

        # Step 4: Backfill existing data
        logger.info("Backfilling user_id on existing rows...")
        counts = _backfill_user_ids(cursor, connection, admin_id)
        for table, count in counts.items():
            logger.info("  %s: %d rows updated", table, count)

        # Step 5: Create user_configs for admin
        cursor.execute(
            "SELECT id FROM user_configs WHERE user_id = ? LIMIT 1",
            (admin_id,),
        )
        if not cursor.fetchone():
            stock_list = os.getenv("STOCK_LIST", "")
            cursor.execute(
                "INSERT INTO user_configs (user_id, stock_list, preferences_json) VALUES (?, ?, '{}')",
                (admin_id, stock_list),
            )
            connection.commit()
            logger.info("Created user_configs row for admin")

    # Step 6: Summary
    logger.info("=" * 50)
    logger.info("Migration complete!")
    if existing_admin is None:
        if plaintext_password:
            logger.info("ADMIN PASSWORD: %s", plaintext_password)
            logger.info("*** SAVE THIS PASSWORD - it will not be shown again ***")
        else:
            logger.info("Admin password: (migrated from existing .admin_password_hash)")
    else:
        logger.info("Admin user already existed, no changes to password")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
