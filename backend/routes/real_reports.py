import os
from fastapi import APIRouter, Query, HTTPException
from typing import Optional
from database import get_database
from config import MONGODB_URI
from pymongo import MongoClient
import re

router = APIRouter(prefix="/real-reports", tags=["Real Threat Intelligence Reports"])

def get_real_reports_collection():
    database = get_database()
    if database is not None:
        # Check if realReports exists in current db or in threat_intelligence
        if "realReports" in database.list_collection_names():
            return database["realReports"]
        
        # Check in threat_intelligence database
        try:
            client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=3000)
            ti_db = client["threat_intelligence"]
            if "realReports" in ti_db.list_collection_names():
                return ti_db["realReports"]
            return database["realReports"]
        except Exception:
            return database["realReports"]
    return None

@router.get("/count")
def get_real_reports_count():
    coll = get_real_reports_collection()
    if coll is not None:
        try:
            count = coll.count_documents({})
            return {
                "totalRealReports": count,
                "connected": True
            }
        except Exception as e:
            return {"totalRealReports": 0, "connected": False, "error": str(e)}
    return {"totalRealReports": 0, "connected": False}

@router.get("")
def get_real_reports(
    search: Optional[str] = Query(None, description="Search term in title, organization, summary"),
    year: Optional[int] = Query(None, description="Filter by year"),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100)
):
    coll = get_real_reports_collection()
    if coll is None:
        return {
            "data": [],
            "page": page,
            "limit": limit,
            "total": 0,
            "totalPages": 0,
            "connected": False
        }

    query = {}
    if search:
        regex = re.compile(search, re.IGNORECASE)
        query["$or"] = [
            {"title": regex},
            {"organization": regex},
            {"summary": regex}
        ]
    if year:
        query["year"] = year

    try:
        total = coll.count_documents(query)
        skip = (page - 1) * limit
        cursor = coll.find(query).sort("year", -1).skip(skip).limit(limit)

        reports = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            if "importedAt" in doc and hasattr(doc["importedAt"], "isoformat"):
                doc["importedAt"] = doc["importedAt"].isoformat()
            reports.append(doc)

        return {
            "data": reports,
            "page": page,
            "limit": limit,
            "total": total,
            "totalPages": (total + limit - 1) // limit if total > 0 else 0,
            "connected": True
        }
    except Exception as e:
        return {
            "data": [],
            "page": page,
            "limit": limit,
            "total": 0,
            "totalPages": 0,
            "connected": False,
            "error": str(e)
        }
