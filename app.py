# app.py - LinkAuth FULL API (Render Ready)
from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
from datetime import datetime, timedelta
import secrets
import hashlib
import requests
import os
from functools import wraps

app = Flask(__name__)
CORS(app)

# MySQL Config (Render Variables)
DB_CONFIG = {
    'host': os.getenv('MYSQLHOST', 'localhost'),
    'user': os.getenv('MYSQLUSER', 'root'),
    'password': os.getenv('MYSQLPASSWORD', ''),
    'database': os.getenv('MYSQLDATABASE', 'linkauth')
}

def get_db():
    return mysql.connector.connect(**DB_CONFIG)

def generate_key():
    return secrets.token_urlsafe(32)

@app.route('/api/auth', methods=['POST'])
def auth():
    data = request.json
    key = data.get('key')
    hwid = data.get('hwid', '')
    ip = request.remote_addr
    
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # Check key validity
    cursor.execute("""
        SELECT * FROM users WHERE `key` = %s AND 
        (expires IS NULL OR expires > NOW()) AND status = 'active'
    """, (key,))
    
    user = cursor.fetchone()
    if not user:
        cursor.execute("INSERT INTO logs (key, ip, action) VALUES (%s, %s, %s)", 
                      (key, ip, 'auth_failed'))
        conn.commit()
        conn.close()
        return jsonify({'success': False, 'message': 'Invalid/expired key'}), 401
    
    # HWID Check
    if user['hwid_locked'] and user['hwid'] != hwid:
        cursor.execute("INSERT INTO logs (key, ip, hwid, action) VALUES (%s, %s, %s, %s)", 
                      (key, ip, hwid, 'hwid_mismatch'))
        conn.commit()
        conn.close()
        return jsonify({'success': False, 'message': 'HWID mismatch'}), 401
    
    # Update last seen + HWID if first time
    cursor.execute("""
        UPDATE users SET last_seen = NOW(), ip = %s, hwid = %s 
        WHERE `key` = %s
    """, (ip, hwid, key))
    
    cursor.execute("INSERT INTO logs (key, ip, hwid, action) VALUES (%s, %s, %s, %s)", 
                  (key, ip, hwid, 'auth_success'))
    conn.commit()
    conn.close()
    
    # Calculate days left
    expires = user['expires']
    days_left = (datetime.fromisoformat(expires) - datetime.now()).days if expires else '∞'
    
    return jsonify({
        'success': True,
        'data': {
            'key': key,
            'username': user['username'],
            'days_left': days_left,
            'hwid_locked': user['hwid_locked'],
            'hwid': user['hwid'],
            'ip': ip,
            'features': user['features'].split(',') if user['features'] else [],
            'usage_today': get_usage_today(key)
        }
    })

@app.route('/api/init', methods=['POST'])
def init():
    data = request.json
    key = data.get('key')
    hwid = data.get('hwid', '')
    ip = request.remote_addr
    
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM users WHERE `key` = %s", (key,))
    user = cursor.fetchone()
    
    if not user or user['hwid'] != '':
        conn.close()
        return jsonify({'success': False, 'message': 'Key invalid or already initialized'}), 400
    
    cursor.execute("UPDATE users SET hwid = %s, ip = %s WHERE `key` = %s", (hwid, ip, key))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'HWID registered'})

@app.route('/api/stats', methods=['GET'])
def stats():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # Dashboard stats
    cursor.execute("SELECT COUNT(*) as total FROM users WHERE status = 'active'")
    total_active = cursor.fetchone()['total']
    
    cursor.execute("SELECT COUNT(*) as total FROM users WHERE status = 'expired'")
    total_expired = cursor.fetchone()['total']
    
    cursor.execute("SELECT COUNT(*) as total FROM users WHERE status = 'banned'")
    total_banned = cursor.fetchone()['total']
    
    cursor.execute("SELECT AVG((expires - NOW())/86400) as avg_days FROM users WHERE status = 'active'")
    avg_days = cursor.fetchone()['avg_days']
    
    conn.close()
    
    return jsonify({
        'success': True,
        'stats': {
            'total_keys': total_active + total_expired + total_banned,
            'active_keys': total_active,
            'expired_keys': total_expired,
            'banned_keys': total_banned,
            'avg_days_left': round(avg_days, 1) if avg_days else 0,
            'hwid_locked_pct': get_hwid_stats()
        }
    })

@app.route('/api/keys', methods=['GET'])
def get_keys():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT `key`, username, hwid_locked, hwid, ip, last_seen,
        CASE 
            WHEN expires IS NULL THEN '∞'
            WHEN expires > NOW() THEN CONCAT(ROUND((expires - NOW())/86400), ' days')
            ELSE 'Expired'
        END as days_left,
        status 
        FROM users ORDER BY created_at DESC LIMIT 50
    """)
    keys = cursor.fetchall()
    conn.close()
    return jsonify({'success': True, 'keys': keys})

def get_usage_today(key):
    conn = get_db()
    cursor = conn.cursor()
    today = datetime.now().strftime('%Y-%m-%d')
    cursor.execute("SELECT COUNT(*) FROM logs WHERE `key` = %s AND DATE(created_at) = %s", 
                  (key, today))
    count = cursor.fetchone()[0]
    conn.close()
    return count

def get_hwid_stats():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE hwid_locked = 1 AND status = 'active'")
    locked = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'active'")
    total = cursor.fetchone()[0]
    conn.close()
    return round((locked/total)*100, 1) if total > 0 else 0

# Discord Bot Webhook Endpoints
@app.route('/api/webhook/create', methods=['POST'])
def webhook_create():
    data = request.json
    days = int(data['days'])
    username = data['username']
    hwid_locked = data.get('hwid_locked', False)
    features = ','.join(data.get('features', []))
    
    key = generate_key()
    expires = datetime.now() + timedelta(days=days)
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (`key`, username, expires, hwid_locked, features, status) 
        VALUES (%s, %s, %s, %s, %s, 'active')
    """, (key, username, expires, hwid_locked, features))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'key': key})

@app.route('/api/webhook/delete', methods=['POST'])
def webhook_delete():
    data = request.json
    key = data['key']
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET status = 'deleted' WHERE `key` = %s", (key,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/webhook/ban', methods=['POST'])
def webhook_ban():
    data = request.json
    key = data['key']
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET status = 'banned' WHERE `key` = %s", (key,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

if __name__ == '__main__':
    # Create tables if not exists
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            `key` VARCHAR(64) UNIQUE NOT NULL,
            username VARCHAR(32),
            expires DATETIME,
            hwid_locked BOOLEAN DEFAULT 0,
            hwid VARCHAR(128),
            ip VARCHAR(45),
            features VARCHAR(256),
            status ENUM('active', 'expired', 'banned', 'deleted') DEFAULT 'active',
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            `key` VARCHAR(64),
            ip VARCHAR(45),
            hwid VARCHAR(128),
            action VARCHAR(32),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()
    
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
