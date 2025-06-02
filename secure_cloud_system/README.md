# Secure Cloud System for SQL Injection Prevention

## Description
This system:
- Prevents SQL injection via input sanitization and parameterized queries.
- Encrypts sensitive data (passwords) using AES-256.
- Uses a capability code mechanism to control access to SQL query execution.
- Provides double-layer security against SQL injection.
- Uses CLI input, no UI.
- Uses lightweight SQLite DB, can be replaced with cloud DB.

## Setup
1. Create a virtual environment (optional):
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows
