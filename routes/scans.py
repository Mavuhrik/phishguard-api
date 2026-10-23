from flask import Blueprint, jsonify, request 
from analyzer.url_validator import validate_url
from analyzer.url_analyzer import analyze_url
from database.models import Scan
from database.session import session_factory
from sqlalchemy import select

scans_bp = Blueprint("scans",__name__)

@scans_bp.route("/scan", methods=["POST"])
def analyze():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error":"invalid or malformed json"}),400
    url = data.get("url")
    if not validate_url(url):
        return jsonify({"error":"invalid url"}),400
    results = analyze_url(url)
    scan = Scan(url = url,
                domain = results["domain"],
                risk_score = results["risk_score"],
                risk_level = results["risk_level"]
                )
    
    with session_factory.begin() as session:
        session.add(scan)
        session.flush()
        scan_id = scan.id
    results["id"] = scan_id
    return jsonify(results),200

@scans_bp.route("/scans/<int:scan_id>", methods=["GET"])
def get_scan (scan_id):
    with session_factory() as session:
        saved_scan = session.get(Scan, scan_id)
        if not saved_scan:
            return jsonify({"error":"scan not found"}),404
        results = {
                       "id": scan_id,
                       "url": saved_scan.url,
                       "domain":saved_scan.domain,
                       "risk_score": saved_scan.risk_score,
                       "risk_level":saved_scan.risk_level,
                       "created_at": (saved_scan.created_at.isoformat() if saved_scan.created_at else None)
                  }
    return jsonify(results),200


@scans_bp.route("/scans", methods=["GET"])
def list_scans():
    with session_factory() as session:
        statement = (select(Scan).order_by(Scan.id.desc()).limit(50))
        scans = session.scalars(statement).all()
        results = [
                   {"id": scan.id,
                    "url": scan.url,
                    "domain": scan.domain,
                    "risk_score": scan.risk_score,
                    "risk_level": scan.risk_level,
                    "created_at": (scan.created_at.isoformat() if scan.created_at else None)
                    }
                    for scan in scans
                    ]
    return jsonify({"scans":results}),200
        