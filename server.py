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
