"""
Database Schema Migration Script
Adds missing columns to cached_asm_scans table
"""

import sqlite3
import os

# Path to the database
DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'ghost.db')

def migrate_schema():
    """Add missing columns to cached_asm_scans table if they don't exist"""

    print(f"[MIGRATION] Connecting to database: {DB_PATH}")

    if not os.path.exists(DB_PATH):
        print(f"[MIGRATION] Database not found at {DB_PATH}")
        print("[MIGRATION] Database will be created when the application starts")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Check if table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cached_asm_scans'")
    table_exists = cursor.fetchone() is not None

    if not table_exists:
        print("[MIGRATION] Table 'cached_asm_scans' does not exist yet")
        print("[MIGRATION] Table will be created when the application starts")
        conn.close()
        return

    # Get existing columns
    cursor.execute("PRAGMA table_info(cached_asm_scans)")
    existing_columns = [row[1] for row in cursor.fetchall()]
    print(f"[MIGRATION] Existing columns: {existing_columns}")

    columns_to_add = [
        ('risk_level', 'VARCHAR(20)'),
        ('vulnerabilities_found', 'INTEGER DEFAULT 0'),
        ('open_ports_count', 'INTEGER DEFAULT 0')
    ]

    for column_name, column_type in columns_to_add:
        if column_name not in existing_columns:
            try:
                sql = f"ALTER TABLE cached_asm_scans ADD COLUMN {column_name} {column_type}"
                print(f"[MIGRATION] Adding column: {column_name}")
                cursor.execute(sql)
                print(f"[MIGRATION] [+] Successfully added {column_name}")
            except sqlite3.OperationalError as e:
                print(f"[MIGRATION] [X] Error adding {column_name}: {e}")
        else:
            print(f"[MIGRATION] [O] Column {column_name} already exists")

    conn.commit()
    conn.close()

    print("[MIGRATION] Schema migration complete!")

if __name__ == "__main__":
    migrate_schema()
