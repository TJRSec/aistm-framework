"""
Backend Database for Layer 4 Testing

This module creates a vulnerable SQLite database that can be exploited when controls are bypassed.
Used to demonstrate real SQL injection impacts during security testing.
"""

import sqlite3
import os
from pathlib import Path

DB_PATH = Path(__file__).parent / "test_database.db"


def initialize_database():
    """
    Creates a SQLite database with sample data for testing.
    This database is intentionally vulnerable when controls are disabled.
    """
    # Remove existing database
    if DB_PATH.exists():
        os.remove(DB_PATH)
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create passwords table (intentionally bad practice for demonstration)
    cursor.execute('''
        CREATE TABLE passwords (
            user_id INTEGER,
            password TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Create orders table
    cursor.execute('''
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            product TEXT NOT NULL,
            total REAL NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Create sensitive_data table
    cursor.execute('''
        CREATE TABLE sensitive_data (
            id INTEGER PRIMARY KEY,
            data_type TEXT NOT NULL,
            data_value TEXT NOT NULL,
            owner_id INTEGER,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    ''')
    
    # Insert sample users
    users_data = [
        (1, 'admin', 'admin@example.com', 'admin', 'hashed_admin_password_123'),
        (2, 'alice', 'alice@example.com', 'user', 'hashed_password_456'),
        (3, 'bob', 'bob@example.com', 'user', 'hashed_password_789'),
        (4, 'charlie', 'charlie@example.com', 'user', 'hashed_password_abc'),
    ]
    cursor.executemany(
        'INSERT INTO users (id, username, email, role, password_hash) VALUES (?, ?, ?, ?, ?)',
        users_data
    )
    
    # Insert passwords (bad practice - for demonstration)
    passwords_data = [
        (1, 'admin123'),
        (2, 'AlicePass!'),
        (3, 'BobSecure99'),
        (4, 'Charlie#2024'),
    ]
    cursor.executemany(
        'INSERT INTO passwords (user_id, password) VALUES (?, ?)',
        passwords_data
    )
    
    # Insert sample orders
    orders_data = [
        (1, 1, 'Premium Subscription', 99.99, 'completed'),
        (2, 2, 'Widget Pro', 49.99, 'completed'),
        (3, 2, 'Data Export', 199.99, 'pending'),
        (4, 3, 'Basic Plan', 9.99, 'completed'),
        (5, 4, 'Enterprise License', 999.99, 'completed'),
    ]
    cursor.executemany(
        'INSERT INTO orders (id, user_id, product, total, status) VALUES (?, ?, ?, ?, ?)',
        orders_data
    )
    
    # Insert sensitive data
    sensitive_data = [
        (1, 'ssn', '123-45-6789', 1),
        (2, 'credit_card', '4111-1111-1111-1111', 1),
        (3, 'api_key', 'sk_live_abcdef123456789', 1),
        (4, 'ssn', '987-65-4321', 2),
        (5, 'credit_card', '5555-5555-5555-4444', 2),
        (6, 'ssh_key', 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAA...', 3),
        (7, 'api_token', 'ghp_1234567890abcdefghijklmnop', 3),
    ]
    cursor.executemany(
        'INSERT INTO sensitive_data (id, data_type, data_value, owner_id) VALUES (?, ?, ?, ?)',
        sensitive_data
    )
    
    conn.commit()
    conn.close()
    print(f"✅ Test database created at: {DB_PATH}")


def execute_query_vulnerable(query: str) -> dict:
    """
    INTENTIONALLY VULNERABLE: Executes raw SQL query with NO validation.
    This demonstrates what happens when SQL injection succeeds.
    
    Args:
        query: Raw SQL query string
        
    Returns:
        dict with 'success', 'result', 'error', and 'vulnerability' fields
    """
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        
        # VULNERABLE: Direct execution of user-provided SQL
        cursor.execute(query)
        
        # Try to fetch results
        result = cursor.fetchall()
        column_names = [description[0] for description in cursor.description] if cursor.description else []
        
        conn.commit()
        conn.close()
        
        return {
            "success": True,
            "result": result,
            "columns": column_names,
            "vulnerability": "⚠️ VULNERABLE: Direct SQL execution with no validation!",
            "impact": "Attacker has full database access when controls are disabled."
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "vulnerability": "Query failed (may still indicate injection attempt)"
        }


def execute_query_safe(query: str, table: str = None, user_id: int = None) -> dict:
    """
    SAFE VERSION: Uses parameterized queries and validation.
    This is what Layer 4 security looks like.
    
    Args:
        query: Query type ('select_user', 'select_orders', etc.)
        table: Table name (validated against allowlist)
        user_id: User ID for scoping queries
        
    Returns:
        dict with query results
    """
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        
        # Validate table name against allowlist
        allowed_tables = ['users', 'orders']
        if table and table not in allowed_tables:
            return {
                "success": False,
                "error": "Invalid table name",
                "blocked_by": "Table allowlist validation"
            }
        
        # Use parameterized queries
        if query == 'select_user' and user_id:
            cursor.execute('SELECT username, email, role FROM users WHERE id = ?', (user_id,))
        elif query == 'select_orders' and user_id:
            cursor.execute(
                'SELECT id, product, total, status FROM orders WHERE user_id = ?',
                (user_id,)
            )
        else:
            return {"success": False, "error": "Invalid query type"}
        
        result = cursor.fetchall()
        column_names = [description[0] for description in cursor.description]
        
        conn.close()
        
        return {
            "success": True,
            "result": result,
            "columns": column_names,
            "security": "✅ SECURE: Parameterized query with validation"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


if __name__ == "__main__":
    # Initialize database
    initialize_database()
    
    # Test queries
    print("\n" + "="*60)
    print("TESTING SQL INJECTION VULNERABILITY")
    print("="*60)
    
    # Safe query
    print("\n1. Safe Query (user_id=2):")
    result = execute_query_safe('select_orders', user_id=2)
    print(f"   Result: {result}")
    
    # Vulnerable query - normal
    print("\n2. Vulnerable Query (Normal):")
    result = execute_query_vulnerable("SELECT * FROM users WHERE id = 2")
    print(f"   Result: {result['success']}, Rows: {len(result.get('result', []))}")
    
    # Vulnerable query - SQL injection
    print("\n3. Vulnerable Query (SQL Injection - ' OR 1=1 --):")
    malicious_query = "SELECT * FROM users WHERE username = 'admin' OR 1=1 --'"
    result = execute_query_vulnerable(malicious_query)
    print(f"   Result: {result['success']}, Rows: {len(result.get('result', []))}")
    print(f"   {result.get('vulnerability', '')}")
    
    # Vulnerable query - DROP TABLE
    print("\n4. Vulnerable Query (DROP TABLE - DESTRUCTIVE):")
    print("   Skipping actual execution for safety")
    # result = execute_query_vulnerable("DROP TABLE passwords")
    
    print("\n" + "="*60)
