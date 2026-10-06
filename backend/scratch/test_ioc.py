import sys
sys.path.insert(0, ".")
from database import get_database

db = get_database()
coll = db['threat_reports']

filters = {
    'ip': {"$or": [{"sourceFeed": {"$regex": "virustotal", "$options": "i"}}, {"reportId": {"$regex": "VT-IP"}}, {"data.raw_indicators": {"$regex": r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"}}]},
    'url': {"$or": [{"sourceFeed": {"$regex": "urlhaus", "$options": "i"}}, {"reportId": {"$regex": "URLHAUS"}}, {"data.raw_indicators": {"$regex": r"^https?://"}}]},
    'domain': {"$or": [{"sourceFeed": {"$regex": "threatfox|botvrij|circl", "$options": "i"}}, {"data.raw_indicators": {"$regex": r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"}}]},
    'hash': {"$or": [{"data.hashes.sha256": {"$regex": r"^[a-fA-F0-9]{64}$", "$ne": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}, {"data.hashes.md5": {"$regex": r"^[a-fA-F0-9]{32}$"}}, {"data.hashes.sha1": {"$regex": r"^[a-fA-F0-9]{40}$"}}]},
    'cve': {"$or": [{"sourceFeed": {"$regex": "cisa", "$options": "i"}}, {"reportId": {"$regex": "CVE", "$options": "i"}}, {"title": {"$regex": "CVE", "$options": "i"}}]}
}

for name, q in filters.items():
    cnt = coll.count_documents(q)
    print(f"Filter {name}: {cnt} matching documents")

