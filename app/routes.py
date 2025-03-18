from flask import Blueprint, render_template, request, jsonify
import os
import sqlite3

main = Blueprint('main', __name__)

# Intentionally vulnerable database connection
def get_db():
    conn = sqlite3.connect('database.db')
    return conn

@main.route('/')
def home():
    return render_template('login.html')

@main.route('/login', methods=['POST'])
def login():
    # Vulnerable to SQL Injection
    username = request.form.get('username')
    password = request.form.get('password')
    
    conn = get_db()
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        return render_template('dashboard.html', username=username)
    return "Login failed"

@main.route('/execute')
def execute_command():
    # Vulnerable to Command Injection
    cmd = request.args.get('cmd', '')
    output = os.popen(cmd).read()
    return output

@main.route('/files')
def read_file():
    # Vulnerable to Path Traversal
    filename = request.args.get('filename', '')
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return content
    except Exception as e:
        return str(e) 