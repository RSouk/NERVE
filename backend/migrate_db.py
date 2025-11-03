"""
Database migration script to add new fingerprinting columns to bait_accesses table
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'ghost.db')

def migrate_database():
    """Add new columns to bait_accesses table"""
    print(f"[MIGRATION] Connecting to database: {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Get existing columns
    cursor.execute("PRAGMA table_info(bait_accesses)")
    existing_columns = [row[1] for row in cursor.fetchall()]
    print(f"[MIGRATION] Existing columns: {existing_columns}")

    # Columns to add
    new_columns = [
        ('accept_language', 'TEXT'),
        ('referer', 'TEXT'),
        ('sec_fetch_headers', 'TEXT'),
        ('attribution_type', 'TEXT'),
        ('evidence_strength', 'TEXT')
    ]

    for column_name, column_type in new_columns:
        if column_name not in existing_columns:
            print(f"[MIGRATION] Adding column: {column_name} ({column_type})")
            try:
                cursor.execute(f"ALTER TABLE bait_accesses ADD COLUMN {column_name} {column_type}")
                print(f"[MIGRATION] SUCCESS: Added {column_name}")
            except Exception as e:
                print(f"[MIGRATION] ERROR: Could not add {column_name}: {e}")
        else:
            print(f"[MIGRATION] Column {column_name} already exists")

    conn.commit()
    conn.close()
    print("[MIGRATION] Migration complete")

if __name__ == "__main__":
    migrate_database()
