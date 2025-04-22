from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)

# Configure CORS
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})

@app.route("/", methods=["GET", "POST", "OPTIONS", "PUT", "DELETE"])
def home():
    response = jsonify({"message": "CORS Misconfigured!"})
    
    # Manually setting CORS headers
    response.headers["Access-Control-Allow-Origin"] = "*"  # Allows all origins
    response.headers["Access-Control-Allow-Credentials"] = "true"  # Allows credentials
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    
    return response

if __name__ == "__main__":
    app.run(debug=True)
