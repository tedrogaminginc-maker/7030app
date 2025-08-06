from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import json

app = Flask(__name__)
CORS(app)

# Load or create user balances
if os.path.exists("balances.json"):
    with open("balances.json", "r") as f:
        balances = json.load(f)
else:
    balances = {}

# Load or create processed transactions
if os.path.exists("processed_tx.json"):
    with open("processed_tx.json", "r") as f:
        processed_tx = json.load(f)
else:
    processed_tx = []

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('.', path)

@app.route('/balance/<user_id>')
def get_balance(user_id):
    return jsonify({"balance": balances.get(user_id, 0)})

@app.route('/adgem_postback')
def adgem_postback():
    user_id = request.args.get('user_id')
    amount = request.args.get('amount')
    tx_id = request.args.get('tx_id')
    event = request.args.get('event')

    if not user_id or not amount or not tx_id:
        return "Missing required parameters", 400

    if tx_id in processed_tx:
        return "Duplicate transaction", 200

    try:
        amount = float(amount)
    except:
        return "Invalid amount", 400

    balances[user_id] = balances.get(user_id, 0) + amount
    processed_tx.append(tx_id)

    with open("balances.json", "w") as f:
        json.dump(balances, f)

    with open("processed_tx.json", "w") as f:
        json.dump(processed_tx, f)

    print(f"[AdGem Postback] Credited {amount} to {user_id} for event: {event} | TX: {tx_id}")
    return "OK", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
