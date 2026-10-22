from flask import Flask, jsonify, request
from routes.scans import scans_bp

app = Flask(__name__)
app.register_blueprint(scans_bp)

@app.route("/")
def home():
    return jsonify({"message": "Phishguard API is running!"}),200


