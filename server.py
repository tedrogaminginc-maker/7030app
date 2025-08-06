from flask import Flask
import os

app = Flask(__name__)

@app.route("/")
def home():
    return "7030App Flask Server is running."

# Optional: endpoint for AdGem/CPX postbacks
@app.route("/postback")
def postback():
    return "Postback received."

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
