from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
import requests
import time
from datetime import datetime, timedelta
from bson.json_util import dumps
from flask_cors import CORS

# Flask app initialization
app = Flask(__name__)
CORS(app)

# MongoDB configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/cve_db"
mongo = PyMongo(app)

# Fetch CVE Data from API (for initial population of the database)
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Fetch CVE data
def fetch_cve_data(offset: int = 0, limit: int = 200):
    params = {"startIndex": offset, "resultsPerPage": limit}
    response = requests.get(API_URL, params=params)
    if response.status_code == 200:
        data = response.json()
        cve_items = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_item = {
                "cveID": cve_data.get("id", ""),
                "description": cve_data.get("descriptions", [{}])[0].get("value", ""),
                "severity": cve_data.get("vulnStatus", "Unknown"),
                "metrics": cve_data.get("metrics", {}),
                "lastModified": cve_data.get("lastModified", ""),
                "publishedDate": cve_data.get("published", ""),
            }
            cve_items.append(cve_item)
        return cve_items
    return []

# Insert CVE Data into MongoDB
def insert_cve_data(cve_data):
    for item in cve_data:
        mongo.db.cves.update_one(
            {"cveID": item["cveID"]}, {"$set": item}, upsert=True
        )

# Paginated CVE data retrieval
@app.route("/cve/page/<int:page>", methods=["GET"])
def get_cve_page(page):
    limit = 15  # Show 15 CVEs per page
    skip = (page - 1) * limit  # Calculate how many records to skip
    cves = mongo.db.cves.find().skip(skip).limit(limit)
    return dumps(cves)

# Search specific CVE by ID
@app.route("/cve/search/<string:cve_id>", methods=["GET"])
def search_cve_by_id(cve_id):
    cve = mongo.db.cves.find_one({"cveID": cve_id})
    if cve:
        return dumps(cve)
    return jsonify({"message": "CVE not found"}), 404

if __name__ == "__main__":
    app.run(debug=True)
