#!/usr/bin/env python3
"""
Vulnerable Python Application for SAST Testing
This file contains intentional security vulnerabilities for testing purposes
"""

import os
import sqlite3
import subprocess
import hashlib
import pickle
import xml.etree.ElementTree as ET
from flask import Flask, request, render_template_string, redirect
import yaml
import mysql.connector

app = Flask(__name__)

# Hardcoded credentials (should be detected by SAST)
SECRET_KEY = "hardcoded-secret-key-123"
DATABASE_PASSWORD = "admin123"
API_TOKEN = "sk-abcd1234567890"

# SQL Injection vulnerability
@app.route('/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: String formatting in SQL query
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return str(result)

# Template Injection (SSTI) vulnerability
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    # VULNERABLE: User input directly in template
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

# Command Injection vulnerability
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    # VULNERABLE: User input in shell command
    result = os.system(f"ping -c 1 {host}")
    return f"Ping result: {result}"

# Path Traversal vulnerability
@app.route('/read_file')
def read_file():
    filename = request.args.get('file')
    # VULNERABLE: No path validation
    try:
        with open(f"/var/log/{filename}", 'r') as f:
            return f.read()
    except:
        return "File not found"

# Insecure deserialization
@app.route('/deserialize', methods=['POST'])
def deserialize():
    data = request.get_data()
    # VULNERABLE: Unpickling untrusted data
    obj = pickle.loads(data)
    return f"Deserialized: {obj}"

# Weak cryptography
def hash_password(password):
    # VULNERABLE: Using MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()

# XML External Entity (XXE) vulnerability
@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    xml_data = request.get_data()
    # VULNERABLE: XML parsing without disabling external entities
    root = ET.fromstring(xml_data)
    return f"Parsed XML: {root.text}"

# YAML deserialization vulnerability
@app.route('/parse_yaml', methods=['POST'])
def parse_yaml():
    yaml_data = request.get_data()
    # VULNERABLE: Using unsafe YAML loader
    data = yaml.load(yaml_data, Loader=yaml.Loader)
    return f"Parsed YAML: {data}"

# Open redirect vulnerability
@app.route('/redirect')
def redirect_user():
    url = request.args.get('url')
    # VULNERABLE: Unvalidated redirect
    return redirect(url)

# Information disclosure
@app.route('/debug')
def debug():
    try:
        # Some operation that might fail
        result = 1 / 0
    except Exception as e:
        # VULNERABLE: Exposing sensitive information in error
        return f"Database error: password={DATABASE_PASSWORD}, error={str(e)}"

# Weak random generation
import random
def generate_session_id():
    # VULNERABLE: Using weak random for session ID
    return str(random.randint(1000, 9999))

# LDAP Injection vulnerability
def authenticate_ldap(username, password):
    import ldap
    # VULNERABLE: User input directly in LDAP filter
    filter_str = f"(&(uid={username})(password={password}))"
    # LDAP query would be executed here
    return filter_str

# Code Injection vulnerability
@app.route('/calc')
def calculate():
    expression = request.args.get('expr')
    # VULNERABLE: Using eval with user input
    try:
        result = eval(expression)
        return f"Result: {result}"
    except:
        return "Invalid expression"

# Subprocess injection
@app.route('/execute')
def execute_command():
    cmd = request.args.get('cmd')
    # VULNERABLE: User input in subprocess
    result = subprocess.check_output(cmd, shell=True)
    return result.decode()

# Insecure file upload
@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    # VULNERABLE: No file type validation
    filename = file.filename
    file.save(f"/uploads/{filename}")
    return f"File {filename} uploaded"

# Race condition vulnerability
counter = 0
@app.route('/increment')
def increment():
    global counter
    # VULNERABLE: Race condition without proper locking
    temp = counter
    counter = temp + 1
    return f"Counter: {counter}"

# Insecure random for cryptographic purposes
import secrets
def generate_weak_token():
    # VULNERABLE: Using time-based seed for crypto
    import time
    random.seed(int(time.time()))
    return random.randint(100000, 999999)

# SQL injection with format strings
def search_products(search_term):
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()
    # VULNERABLE: % formatting in SQL
    query = "SELECT * FROM products WHERE name LIKE '%%%s%%'" % search_term
    cursor.execute(query)
    return cursor.fetchall()

# Buffer overflow potential (in C extension)
def vulnerable_buffer():
    # This would be vulnerable in C, shown for completeness
    large_input = "A" * 10000
    # In actual C code: strcpy(buffer, large_input) without bounds checking
    return large_input

# Missing authentication
@app.route('/admin/delete_user/<user_id>')
def delete_user(user_id):
    # VULNERABLE: No authentication check for admin function
    # Delete user logic here
    return f"User {user_id} deleted"

# Timing attack vulnerability
def check_password(input_password, stored_password):
    # VULNERABLE: Character-by-character comparison allows timing attacks
    if len(input_password) != len(stored_password):
        return False
    
    for i in range(len(input_password)):
        if input_password[i] != stored_password[i]:
            return False
    return True

# Regular expression DoS (ReDoS)
import re
def validate_email(email):
    # VULNERABLE: Catastrophic backtracking in regex
    pattern = r'^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$'
    # This pattern can cause ReDoS with specially crafted input
    return re.match(pattern, email + "a" * 1000)

# Insecure direct object reference
@app.route('/profile/<user_id>')
def get_profile(user_id):
    # VULNERABLE: No authorization check
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM profiles WHERE user_id = ?", (user_id,))
    return str(cursor.fetchone())

# Log injection
import logging
def log_user_action(username, action):
    # VULNERABLE: Unvalidated input in log message
    logging.info(f"User {username} performed action: {action}")

if __name__ == '__main__':
    # VULNERABLE: Debug mode enabled in production
    app.run(debug=True, host='0.0.0.0')