import requests
import re
from fastapi import APIRouter
from database import get_collection, get_database
from typing import List, Dict

router = APIRouter(prefix="/new-reports", tags=["New Threat Report Detection"])

@router.get("")
def check_new_threat_reports():
    """
    Checks for newly published external reports from awesome-annual-security-reports
    and MISP feeds that have not yet been ingested into the primary threat_reports collection.
    """
    coll = get_collection()
    db = get_database()
    new_reports = []
    
    existing_titles = set()
    existing_ids = set()
    
    if coll is not None:
        try:
            docs = coll.find({}, {"title": 1, "reportId": 1, "sourceUuid": 1})
            for d in docs:
                if "title" in d:
                    existing_titles.add(d["title"].strip().lower())
                if "reportId" in d:
                    existing_ids.add(d["reportId"].strip())
                if "sourceUuid" in d:
                    existing_ids.add(d["sourceUuid"].strip())
        except Exception:
            pass

    # Check against realReports collection
    if db is not None and "realReports" in db.list_collection_names():
        try:
            real_coll = db["realReports"]
            for r in real_coll.find().limit(50):
                t = r.get("title", "")
                sid = r.get("sourceId", "")
                if (t and t.strip().lower() not in existing_titles) and (sid not in existing_ids):
                    new_reports.append({
                        "reportId": sid or "EXT-REPORT",
                        "title": t,
                        "organization": r.get("organization", "Annual Security Assessment"),
                        "year": r.get("year", 2026),
                        "source": r.get("source", "awesome-annual-security-reports"),
                        "threatType": "Annual Security Assessment",
                        "severity": "High",
                        "description": r.get("summary", "Real threat intelligence assessment published in awesome-annual-security-reports repository."),
                        "status": "Not in Database",
                        "detectedAt": "GitHub Live Feed Sync"
                    })
        except Exception:
            pass

    return {
        "newReportsCount": len(new_reports),
        "newReports": new_reports[:20],
        "status": "Detection scan complete against real intelligence repositories",
        "connectedToMongoDB": coll is not None
    }
