from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
from datetime import datetime, timedelta
import secrets
import os
import json

app = Flask(__name__)
CORS(app)

def get_db():
    conn = sqlite3.connect('linkauth.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            username TEXT,
            expires TEXT,
            hwid_locked INTEGER DEFAULT 0,
            hwid TEXT,
            ip TEXT,
            features TEXT,
            status TEXT DEFAULT 'active',
            last_seen TEXT DEFAULT (datetime('now')),
            created_at TEXT DEFAULT (datetime('now'))
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT,
            ip TEXT,
            hwid TEXT,
            action TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/api/auth', methods=['POST'])
def auth():
    data = request.json
    key = data.get('key')
    hwid = data.get('hwid', '')
    ip = request.remote_addr
    
    conn = get_db()
    
    # Check key validity
    cursor = conn.execute("""
        SELECT * FROM users WHERE key = ? AND 
        (expires IS NULL OR expires > datetime('now')) AND status = 'active'
    """, (key,))
    
    user = cursor.fetchone()
    if not user:
        conn.execute("INSERT INTO logs (key, ip, action) VALUES (?, ?, ?)", 
                    (key, ip, 'auth_failed'))
        conn.commit()
        conn.close()
        return jsonify({'success': False, 'message': 'Invalid/expired key'}), 401
    
    # HWID check
    if user['hwid_locked'] and user['hwid'] != hwid:
        conn.execute("INSERT INTO logs (key, ip, hwid, action) VALUES (?, ?, ?, ?)", 
                    (key, ip, hwid, 'hwid_mismatch'))
        conn.commit()
        conn.close()
        return jsonify({'success': False, 'message': 'HWID mismatch'}), 401
    
    # Update last seen
    conn.execute("""
        UPDATE users SET last_seen = datetime('now'), ip = ?, hwid = ? 
        WHERE key = ?
    """, (ip, hwid, key))
    
    conn.execute("INSERT INTO logs (key, ip, hwid, action) VALUES (?, ?, ?, ?)", 
                (key, ip, hwid, 'auth_success'))
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'data': {
            'key': key,
            'username': user['username'],
            'hwid_locked': bool(user['hwid_locked']),
            'hwid': user['hwid'],
            'ip': ip
        }
    })

@app.route('/api/stats', methods=['GET'])
def stats():
    conn = get_db()
    cursor = conn.execute("SELECT COUNT(*) as total FROM users WHERE status = 'active'")
    active = cursor.fetchone()['total']
    cursor = conn.execute("SELECT COUNT(*) as total FROM users")
    total = cursor.fetchone()['total']
    conn.close()
    return jsonify({'success': True, 'active_keys': active, 'total_keys': total})

@app.route('/api/keys', methods=['GET'])
def get_keys():
    conn = get_db()
    cursor = conn.execute("""
        SELECT key, username, hwid_locked, hwid, ip, status, last_seen 
        FROM users ORDER BY created_at DESC LIMIT 50
    """)
    keys = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({'success': True, 'keys': keys})

@app.route('/api/webhook/create', methods=['POST'])
def create_key():
    data = request.json
    key = secrets.token_urlsafe(32)
    expires = (datetime.now() + timedelta(days=int(data.get('days', 30)))).isoformat()
    
    conn = get_db()
    conn.execute("""
        INSERT INTO users (key, username, expires, hwid_locked, features) 
        VALUES (?, ?, ?, ?, ?)
    """, (key, data.get('username', 'User'), expires, data.get('hwid_locked', 0), ''))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'key': key})

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
