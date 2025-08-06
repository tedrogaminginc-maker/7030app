from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os

app = Flask(__name__)
CORS(app)

DATA_FILE = "balances.json"

def load_data():
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

@app.route("/")
def index():
    return "✅ 70/30 Earnings App Backend Running"

@app.route("/balance")
def get_balance():
    user = request.args.get("user", "").strip().lower()
    if not user:
        return jsonify({"error": "Missing user"}), 400

    data = load_data()
    balance = float(data.get(user, 0))
    return jsonify({"balance": round(balance, 4)})

@app.route("/watch_ad")
def watch_ad():
    user = request.args.get("user", "").strip().lower()
    if not user:
        return jsonify({"error": "Missing user"}), 400

    data = load_data()
    current = float(data.get(user, 0))
    current += 0.007  # 70% of $0.01 = $0.007
    data[user] = round(current, 4)
    save_data(data)
    return jsonify({"message": "🤑 Ad watched! $0.007 added."})

@app.route("/postback/cpx", methods=["GET"])
def postback_cpx():
    user = request.args.get("ext_user_id", "").strip().lower()
    payout = request.args.get("payout", "0")

    try:
        payout = float(payout)
        earned = round(payout * 0.7, 4)
    except ValueError:
        return "Invalid payout", 400

    if not user:
        return "Missing user", 400

    data = load_data()
    data[user] = round(float(data.get(user, 0)) + earned, 4)
    save_data(data)
    return "OK"

@app.route("/postback/adgem", methods=["GET"])
def postback_adgem():
    user = request.args.get("subid", "").strip().lower()
    payout = request.args.get("payout", "0")

    try:
        payout = float(payout)
        earned = round(payout * 0.7, 4)
    except ValueError:
        return "Invalid payout", 400

    if not user:
        return "Missing user", 400

    data = load_data()
    data[user] = round(float(data.get(user, 0)) + earned, 4)
    save_data(data)
    return "OK"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
