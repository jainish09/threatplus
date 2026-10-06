import os
import re
import requests
from datetime import datetime
from pymongo import MongoClient, UpdateOne
from dotenv import load_dotenv

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")

if not MONGODB_URI:
    raise RuntimeError("MONGODB_URI not found in .env")

README_URL = (
    "https://raw.githubusercontent.com/"
    "jacobdjwilson/awesome-annual-security-reports/main/README.md"
)

DB_NAME = "threat_intelligence"
COLLECTION_NAME = "realReports"


def normalize(text):
    return re.sub(r"\s+", " ", text).strip()


print("[*] Downloading real report metadata from GitHub...")

response = requests.get(README_URL, timeout=30)
response.raise_for_status()

readme = response.text

print("[+] README downloaded")


# Matches lines such as:
# * Organization - Report Title (2026) - Summary
pattern = re.compile(
    r"^\s*[\*\-]\s+"
    r"(.+?)\s+-\s+"
    r"(.+?)\s+\((20\d{2})\)"
    r"(?:\s+-\s+(.*))?$"
)

reports = []

for line in readme.splitlines():

    match = pattern.match(line)

    if not match:
        continue

    organization = normalize(match.group(1))
    title = normalize(match.group(2))
    year = int(match.group(3))
    summary = normalize(match.group(4) or "")

    source_id = (
        f"{organization.lower()}|"
        f"{title.lower()}|"
        f"{year}"
    )

    reports.append({
        "sourceId": source_id,
        "organization": organization,
        "title": title,
        "year": year,
        "summary": summary,
        "source": "awesome-annual-security-reports",
        "githubUrl": (
            "https://github.com/"
            "jacobdjwilson/awesome-annual-security-reports"
        ),
        "importedAt": datetime.utcnow()
    })


print(f"[*] Reports found: {len(reports)}")


client = MongoClient(MONGODB_URI)

db = client[DB_NAME]
collection = db[COLLECTION_NAME]


operations = []

for report in reports:

    operations.append(
        UpdateOne(
            {"sourceId": report["sourceId"]},
            {"$set": report},
            upsert=True
        )
    )


if operations:
    result = collection.bulk_write(operations)

    print("[+] Import completed")
    print(f"    Inserted: {result.upserted_count}")
    print(f"    Updated:  {result.modified_count}")


print(
    f"[+] Total real reports in MongoDB: "
    f"{collection.count_documents({})}"
)

client.close()

print("[+] Done!")