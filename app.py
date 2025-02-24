from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
from flask_cors import CORS
from bson.json_util import dumps
import requests

app = Flask(__name__)
CORS(app)

# MongoDB setup
app.config["MONGO_URI"] = "mongodb://localhost:27017/cve_db"
mongo = PyMongo(app)

# Get paginated CVE data
@app.route("/cve/page/<int:page>", methods=["GET"])
def get_cve_page(page):
    limit = 10  # Show 10 CVEs per page
    skip = (page - 1) * limit
    total_cves = mongo.db.cves.count_documents({})
    
    cves = mongo.db.cves.find().skip(skip).limit(limit)
    return jsonify({
        "cves": list(cves),
        "total_pages": (total_cves // limit) + (1 if total_cves % limit > 0 else 0)
    })

# Search CVE by ID
@app.route("/cve/search/<string:cve_id>", methods=["GET"])
def search_cve_by_id(cve_id):
    cve = mongo.db.cves.find_one({"cveID": cve_id})
    if cve:
        return dumps({"cves": [cve], "total_pages": 1})
    return jsonify({"message": "CVE not found"}), 404

# Filter CVEs by CVSS severity and date
@app.route("/cve/filter", methods=["GET"])
def filter_cve():
    severity = request.args.get("cvss")
    date = request.args.get("date")
    query = {}

    if severity:
        query["severity"] = severity.capitalize()

    if date:
        query["publishedDate"] = {"$gte": date}

    total_cves = mongo.db.cves.count_documents(query)
    cves = mongo.db.cves.find(query).limit(10)

    return jsonify({
        "cves": list(cves),
        "total_pages": (total_cves // 10) + (1 if total_cves % 10 > 0 else 0)
    })

if __name__ == "__main__":
    app.run(debug=True)
