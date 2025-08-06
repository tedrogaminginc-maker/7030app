from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import os
import secrets

app = Flask(__name__)
CORS(app)

# Init DB if not exists
if not os.path.exists("users.db"):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("CREATE TABLE users (email TEXT PRIMARY KEY, password TEXT, balance REAL DEFAULT 0)")
    conn.commit()
    conn.close()

@app.route("/")
def home():
    return "✅ 70/30 Backend Running"

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Missing email or password"}), 400

    conn = sqlite3.connect("users.db")
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE email = ?", (email,))
    if c.fetchone():
        return jsonify({"error": "Email already registered"}), 400

    c.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
    conn.commit()
    conn.close()

    return jsonify({"message": "Account created successfully!"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, password))
    user = c.fetchone()
    conn.close()

    if user:
        return jsonify({"message": "Login successful!"})
    else:
        return jsonify({"error": "Invalid email or password"}), 401

@app.route("/balance", methods=["GET"])
def get_balance():
    user = request.args.get("user")
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT balance FROM users WHERE email = ?", (user,))
    result = c.fetchone()
    conn.close()
    if result:
        return jsonify({"balance": result[0]})
    else:
        return jsonify({"error": "User not found"}), 404

@app.route("/update-balance", methods=["POST"])
def update_balance():
    data = request.json
    email = data.get("email")
    amount = float(data.get("amount"))

    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("UPDATE users SET balance = balance + ? WHERE email = ?", (amount, email))
    conn.commit()
    conn.close()
    return jsonify({"message": "Balance updated"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
