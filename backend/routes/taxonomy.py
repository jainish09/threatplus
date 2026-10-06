from fastapi import APIRouter, HTTPException
from database import get_database

router = APIRouter(tags=["Taxonomy"])

TAXONOMY_DEFINITIONS = [
    {"taxonomyCode": "TAX-01", "name": "Threat-Actors", "icon": "🎭", "slug": "threat-actors", "description": "APT groups, state-sponsored campaigns, and adversary profiling."},
    {"taxonomyCode": "TAX-02", "name": "Vulnerabilities", "icon": "🛡️", "slug": "vulnerabilities", "description": "CVE zero-day flaws, exploitation vectors, and software bugs."},
    {"taxonomyCode": "TAX-03", "name": "Ransomware", "icon": "🔒", "slug": "ransomware", "description": "Extortionware, double-extortion syndicates, and lockbit telemetry."},
    {"taxonomyCode": "TAX-04", "name": "Patches", "icon": "🩹", "slug": "patches", "description": "Vendor security advisories, bug fixes, and patch management."},
    {"taxonomyCode": "TAX-05", "name": "Malware", "icon": "🦠", "slug": "malware", "description": "Trojans, stealers, loaders, botnets, and obfuscated payloads."},
    {"taxonomyCode": "TAX-06", "name": "Government", "icon": "🏛️", "slug": "government", "description": "Federal directives, CISA advisories, and defense guidelines."},
    {"taxonomyCode": "TAX-07", "name": "Mobile", "icon": "📱", "slug": "mobile", "description": "Android/iOS spyware, mobile malware, and MDM compromises."},
    {"taxonomyCode": "TAX-08", "name": "Cloud", "icon": "☁️", "slug": "cloud", "description": "AWS/Azure/GCP cloud posture, container, and IAM breaches."},
    {"taxonomyCode": "TAX-09", "name": "IoT", "icon": "📡", "slug": "iot", "description": "Firmware exploits, edge gateway attacks, and Mirai botnets."},
    {"taxonomyCode": "TAX-10", "name": "Cryptography", "icon": "🔑", "slug": "cryptography", "description": "Post-quantum transitions, ransomware cryptors, and crypto-jacking."},
    {"taxonomyCode": "TAX-11", "name": "Compromised", "icon": "⚠️", "slug": "compromised", "description": "Exfiltrated credentials, credential stuffing, and session hijack."}
]

@router.get("/taxonomy")
def get_taxonomy_categories():
    db = get_database()
    if db is None:
        raise HTTPException(status_code=503, detail="Database connection offline")
        
    rep_col = db["threat_reports"]
    total_docs = rep_col.count_documents({})

    # Aggregate counts by taxonomyCode and threatType
    counts_map = {}
    agg = list(rep_col.aggregate([
        {"$group": {"_id": "$threatType", "count": {"$sum": 1}}}
    ]))
    for a in agg:
        if a.get("_id"):
            counts_map[a["_id"]] = a["count"]

    agg_code = list(rep_col.aggregate([
        {"$group": {"_id": "$taxonomyCode", "count": {"$sum": 1}}}
    ]))
    for a in agg_code:
        if a.get("_id"):
            counts_map[a["_id"]] = a["count"]

    categories = []
    for td in TAXONOMY_DEFINITIONS:
        item = dict(td)
        item["reportCount"] = counts_map.get(td["name"], 0) or counts_map.get(td["taxonomyCode"], 0)
        categories.append(item)

    return {
        "status": "success",
        "totalTaxonomies": len(categories),
        "totalDocuments": total_docs,
        "taxonomyCategories": categories
    }
