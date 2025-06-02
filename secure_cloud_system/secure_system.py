import sqlite3
import argparse
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# AES-256 Encryption Helper
class AES256Cipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        data = data.encode('utf-8')
        cipher = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return iv + ":" + ct

    def decrypt(self, enc_data):
        iv, ct = enc_data.split(':')
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ct)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')


# Database handler
class SecureDB:
    def __init__(self, db_name, cipher):
        self.conn = sqlite3.connect(db_name)
        self.cipher = cipher
        self.init_db()

    def init_db(self):
        cursor = self.conn.cursor()
        # User table with encrypted password
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        self.conn.commit()

    # Add user with encrypted password
    def add_user(self, username, password):
        encrypted_password = self.cipher.encrypt(password)
        cursor = self.conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, encrypted_password))
            self.conn.commit()
            print(f"User {username} added successfully.")
        except sqlite3.IntegrityError:
            print("Error: Username already exists.")

    # Validate login by decrypting stored password and comparing
    def validate_user(self, username, password):
        cursor = self.conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            stored_enc_password = row[0]
            stored_password = self.cipher.decrypt(stored_enc_password)
            if stored_password == password:
                print("Login successful.")
                return True
            else:
                print("Invalid password.")
        else:
            print("Username not found.")
        return False

    # Secure query execution - layer 1: parameterized query
    def secure_query(self, sql, params):
        cursor = self.conn.cursor()
        cursor.execute(sql, params)
        return cursor.fetchall()


# Capability code manager
class CapabilityManager:
    def __init__(self):
        # In real system, this would be more sophisticated
        self.valid_codes = set(["ABC123XYZ"])  # Example hardcoded valid code

    def validate_code(self, code):
        return code in self.valid_codes


# Input validation for SQL injection (layer 2)
def input_sanitization_check(text):
    # Very basic check - forbid common SQL injection patterns
    blacklist = [";", "--", "/*", "*/", "xp_", "exec", "union", "drop", "insert", "delete", "update", "select"]
    text_lower = text.lower()
    for pattern in blacklist:
        if pattern in text_lower:
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description="Secure Cloud DB CLI")
    parser.add_argument("action", choices=["adduser", "login", "query"], help="Action to perform")
    parser.add_argument("--username", type=str, help="Username")
    parser.add_argument("--password", type=str, help="Password")
    parser.add_argument("--capcode", type=str, help="Capability code")
    parser.add_argument("--sql", type=str, help="SQL query (only select allowed)")
    args = parser.parse_args()

    # AES key (must be 32 bytes for AES-256)
    key = b'0123456789abcdef0123456789abcdef'  # For demo only! Keep secret in real use

    cipher = AES256Cipher(key)
    db = SecureDB("securecloud.db", cipher)
    cap_manager = CapabilityManager()

    # Check capability code for actions except adduser/login
    if args.action == "query":
        if not args.capcode or not cap_manager.validate_code(args.capcode):
            print("Invalid or missing capability code.")
            return
        if not args.sql:
            print("SQL query is required for query action.")
            return
        # Only allow SELECT queries for security
        if not args.sql.strip().lower().startswith("select"):
            print("Only SELECT queries are allowed.")
            return
        # Sanitize SQL input
        if not input_sanitization_check(args.sql):
            print("SQL input contains forbidden patterns, possible injection detected!")
            return

        # Execute safely
        try:
            # Use parameterized query with no parameters here (demo)
            results = db.secure_query(args.sql, ())
            print("Query Results:")
            for row in results:
                print(row)
        except Exception as e:
            print(f"Query execution error: {e}")

    elif args.action == "adduser":
        if not args.username or not args.password:
            print("Username and password are required to add a user.")
            return
        db.add_user(args.username, args.password)

    elif args.action == "login":
        if not args.username or not args.password:
            print("Username and password are required to login.")
            return
        db.validate_user(args.username, args.password)


if __name__ == "__main__":
    main()
