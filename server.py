from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import smtplib
from email.mime.text import MIMEText
import os
import random

app = Flask(__name__)
CORS(app)

# Use environment variables for email credentials
EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASS = os.getenv('EMAIL_PASS')

# ======================= DATABASE HELPERS ===========================

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            password TEXT,
            balance REAL DEFAULT 0
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS reset_codes (
            email TEXT,
            code TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# ======================= ACCOUNT SYSTEM =============================

@app.route('/create_account', methods=['POST'])
def create_account():
    data = request.json
    email = data['email']
    password = data['password']
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE email = ?', (email,))
    if c.fetchone():
        conn.close()
        return jsonify({"message": "Account already exists"}), 409
    c.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, password))
    conn.commit()
    conn.close()
    return jsonify({"message": "Account created"}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data['email']
    password = data['password']
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE email = ? AND password = ?', (email, password))
    user = c.fetchone()
    conn.close()
    if user:
        return jsonify({"message": "Login successful"}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    return jsonify({"message": "Logged out"}), 200

# =================== PASSWORD RESET SYSTEM ==========================

@app.route('/send_reset_code', methods=['POST'])
def send_reset_code():
    data = request.json
    email = data['email']
    code = str(random.randint(100000, 999999))

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE email = ?', (email,))
    if not c.fetchone():
        conn.close()
        return jsonify({"message": "Email not found"}), 404

    c.execute('INSERT INTO reset_codes (email, code) VALUES (?, ?)', (email, code))
    conn.commit()
    conn.close()

    try:
        msg = MIMEText(f"Your 70/30 Earnings reset code is: {code}")
        msg['Subject'] = 'Password Reset Code'
        msg['From'] = EMAIL_USER
        msg['To'] = email

        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, [email], msg.as_string())
        server.quit()
        return jsonify({"message": "Reset code sent"}), 200
    except Exception as e:
        return jsonify({"message": f"Failed to send email: {str(e)}"}), 500

@app.route('/verify_reset_code', methods=['POST'])
def verify_reset_code():
    data = request.json
    email = data['email']
    code = data['code']
    new_password = data['new_password']

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM reset_codes WHERE email = ? AND code = ?', (email, code))
    if not c.fetchone():
        conn.close()
        return jsonify({"message": "Invalid code"}), 400

    c.execute('UPDATE users SET password = ? WHERE email = ?', (new_password, email))
    conn.commit()
    conn.close()
    return jsonify({"message": "Password updated"}), 200

# =================== BALANCE AND WITHDRAWALS ========================

@app.route('/balance', methods=['GET'])
def balance():
    user = request.args.get('user')
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT balance FROM users WHERE email = ?', (user,))
    result = c.fetchone()
    conn.close()
    if result:
        return jsonify({"balance": result[0]})
    else:
        return jsonify({"balance": 0})

@app.route('/update_balance', methods=['POST'])
def update_balance():
    data = request.json
    email = data['email']
    amount = float(data['amount'])

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT balance FROM users WHERE email = ?', (email,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"message": "User not found"}), 404

    new_balance = row[0] + amount
    c.execute('UPDATE users SET balance = ? WHERE email = ?', (new_balance, email))
    conn.commit()
    conn.close()
    return jsonify({"balance": new_balance}), 200

# =================== SERVER STARTUP ================================

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=10000)
