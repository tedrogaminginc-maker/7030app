from flask import Flask, request, send_from_directory
import os
from datetime import datetime

app = Flask(__name__)

# Create balances and views folder if not exist
os.makedirs('balances', exist_ok=True)
os.makedirs('views', exist_ok=True)

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/balance')
def balance():
    user = request.args.get('user')
    if not user:
        return 'Missing user', 400
    balance_file = f'balances/{user}.txt'
    if not os.path.exists(balance_file):
        return '0.00'
    with open(balance_file, 'r') as f:
        return f.read()

@app.route('/views')
def views():
    user = request.args.get('user')
    if not user:
        return 'Missing user', 400
    views_file = f'views/{user}.txt'
    if not os.path.exists(views_file):
        return '0'
    with open(views_file, 'r') as f:
        return f.read()

@app.route('/watch')
def watch():
    user = request.args.get('user')
    if not user:
        return 'Missing user', 400

    views_file = f'views/{user}.txt'
    balance_file = f'balances/{user}.txt'

    # Load views
    views = 0
    if os.path.exists(views_file):
        with open(views_file, 'r') as f:
            views = int(f.read())
    if views >= 30:
        return 'Limit reached', 403

    # Add $0.01 reward
    balance = 0.0
    if os.path.exists(balance_file):
        with open(balance_file, 'r') as f:
            balance = float(f.read())
    balance += 0.01
    with open(balance_file, 'w') as f:
        f.write(str(balance))

    # Update views
    views += 1
    with open(views_file, 'w') as f:
        f.write(str(views))

    # Log it
    with open('history.txt', 'a') as f:
        f.write(f"{user},0.01 (ad),{datetime.now()}\n")

    return 'OK'

@app.route('/postback')
def postback():
    user = request.args.get('user')
    payout = request.args.get('payout')

    if not user or not payout:
        return 'Missing parameters', 400

    try:
        payout = float(payout)
        reward = payout * 0.70  # No rounding
    except ValueError:
        return 'Invalid payout', 400

    # Log reward to history
    with open('history.txt', 'a') as f:
        f.write(f"{user},{reward},{datetime.now()}\n")

    # Update balance
    balance_file = f"balances/{user}.txt"
    if os.path.exists(balance_file):
        with open(balance_file, 'r') as f:
            balance = float(f.read())
    else:
        balance = 0.0

    balance += reward
    with open(balance_file, 'w') as f:
        f.write(str(balance))  # No rounding

    return "OK", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
