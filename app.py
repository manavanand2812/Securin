from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
import requests
import time
from datetime import datetime, timedelta
from pydantic import BaseModel
from bson.json_util import dumps
from flask_cors import CORS

# Flask app initialization
app = Flask(__name__)
CORS(app)

# MongoDB configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/cve_db"
mongo = PyMongo(app)

# CVE API URL
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Pydantic Models (to structure data, but not used in Flask)
class CVEMetrics(BaseModel):
    cvssData: dict

class CVEItem(BaseModel):
    cveID: str
    description: str
    severity: str
    metrics: CVEMetrics
    lastModified: str
    publishedDate: str

# Fetch CVE Data from API
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

# Clean and De-duplicate Data
def clean_and_deduplicate(data):
    seen = set()
    cleaned_data = []
    for item in data:
        if item["cveID"] and item["cveID"] not in seen:
            cleaned_data.append(item)
            seen.add(item["cveID"])
    return cleaned_data

# Insert CVE Data into MongoDB
def insert_cve_data(cve_data):
    for item in cve_data:
        mongo.db.cves.update_one(
            {"cveID": item["cveID"]}, {"$set": item}, upsert=True
        )

# Periodic Sync Function
def sync_cve_data():
    offset = 0
    limit = 200
    while True:
        data = fetch_cve_data(offset, limit)
        if not data:
            break
        cleaned_data = clean_and_deduplicate(data)
        insert_cve_data(cleaned_data)
        offset += limit
        time.sleep(5)

@app.route("/sync", methods=["GET"])
def start_sync():
    sync_cve_data()  # Sync in real-time, or you can run it in a background task.
    return jsonify({"message": "CVE data synchronization started"}), 200

@app.route("/cve/<string:cve_id>", methods=["GET"])
def get_cve_by_id(cve_id):
    cve = mongo.db.cves.find_one({"cveID": cve_id})
    if cve:
        return dumps(cve)
    return jsonify({"message": "CVE not found"}), 404

@app.route("/cve/year/<int:year>", methods=["GET"])
def get_cve_by_year(year):
    cves = mongo.db.cves.find({"publishedDate": {"$regex": str(year)}})
    return dumps(cves)

@app.route("/cve/score", methods=["GET"])
def get_cve_by_score():
    score = request.args.get("score", type=float)
    cves = mongo.db.cves.find({"metrics.cvssMetricV3.cvssData.baseScore": score})
    return dumps(cves)

@app.route("/cve/modified", methods=["GET"])
def get_cve_by_modified_days():
    days = request.args.get("days", type=int)
    date_limit = datetime.utcnow() - timedelta(days=days)
    cves = mongo.db.cves.find({"lastModified": {"$gte": date_limit.isoformat()}})
    return dumps(cves)

if __name__ == "__main__":
    app.run(debug=True)
