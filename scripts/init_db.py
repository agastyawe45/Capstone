import sqlite3
import os

def init_db():
    # Ensure we're in the Capstone directory
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database.db')
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Create users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    
    # Add test users
    c.execute('INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)',
             ('admin', 'admin123'))
    
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db() 