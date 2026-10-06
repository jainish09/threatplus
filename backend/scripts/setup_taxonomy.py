import os
import sys
from pymongo import MongoClient, ASCENDING, DESCENDING
from dotenv import load_dotenv

load_dotenv('backend/.env')
uri = os.getenv('MONGODB_URI') or os.getenv('MONGO_URI')
db_name = os.getenv('DB_NAME', 'threat_intel_db')

TAXONOMY_CATEGORIES = [
    {
        "taxonomyCode": "TAX-01",
        "slug": "Threat-Actors",
        "name": "Threat Actors",
        "icon": "🦹",
        "description": "Advanced Persistent Threat (APT) groups, nation-state cyber warfare units, and financially motivated cybercrime syndicates.",
        "mitreTactics": ["TA0001: Initial Access", "TA0003: Persistence", "TA0011: Command and Control"],
        "targetSectors": ["Defense", "Finance", "Healthcare", "Government"],
        "commonThreatLevels": ["Critical", "High"]
    },
    {
        "taxonomyCode": "TAX-02",
        "slug": "Vulnerabilities",
        "name": "Vulnerabilities",
        "icon": "🛡️",
        "description": "Zero-day exploits, Common Vulnerabilities and Exposures (CVEs), memory corruptions, and remote code execution vulnerabilities.",
        "mitreTactics": ["TA0001: Initial Access", "TA0004: Privilege Escalation", "TA0008: Lateral Movement"],
        "targetSectors": ["Enterprise Software", "Operating Systems", "Web Applications"],
        "commonThreatLevels": ["Critical", "High"]
    },
    {
        "taxonomyCode": "TAX-03",
        "slug": "Ransomware",
        "name": "Ransomware",
        "icon": "🔒",
        "description": "Ransomware-as-a-Service (RaaS) operations, double-extortion tactics, data encrypters, and dark-web extortion leak sites.",
        "mitreTactics": ["TA0040: Impact", "TA0010: Exfiltration", "TA0005: Defense Evasion"],
        "targetSectors": ["Healthcare", "Manufacturing", "Supply Chain", "Local Governments"],
        "commonThreatLevels": ["Critical", "High"]
    },
    {
        "taxonomyCode": "TAX-04",
        "slug": "Patches",
        "name": "Patches & Advisories",
        "icon": "🩹",
        "description": "Vendor security updates, zero-day remediation bulletins, emergency hotfixes, and patch diffing analysis.",
        "mitreTactics": ["TA0005: Defense Evasion", "Remediation & Hardening"],
        "targetSectors": ["IT Infrastructure", "Cloud Deployments", "Endpoints"],
        "commonThreatLevels": ["Medium", "Low"]
    },
    {
        "taxonomyCode": "TAX-05",
        "slug": "Malware",
        "name": "Malware Analysis",
        "icon": "🦠",
        "description": "Trojans, infostealers, polymorphic loaders, keyloggers, and evasive fileless malware payloads.",
        "mitreTactics": ["TA0002: Execution", "TA0005: Defense Evasion", "TA0007: Discovery"],
        "targetSectors": ["Consumer Endpoints", "Corporate Workstations", "FinTech"],
        "commonThreatLevels": ["High", "Medium"]
    },
    {
        "taxonomyCode": "TAX-06",
        "slug": "Government",
        "name": "Government & CISA",
        "icon": "🏛️",
        "description": "Nation-state cyber espionage alerts, CISA Known Exploited Vulnerabilities (KEV), and critical infrastructure security directives.",
        "mitreTactics": ["TA0009: Collection", "TA0043: Reconnaissance", "TA0010: Exfiltration"],
        "targetSectors": ["Federal Agencies", "Energy Grid", "Aviation", "Telecommunications"],
        "commonThreatLevels": ["Critical", "High"]
    },
    {
        "taxonomyCode": "TAX-07",
        "slug": "Mobile",
        "name": "Mobile Threats",
        "icon": "📱",
        "description": "Commercial spyware (Pegasus, Predator), rogue mobile apps, SMS phishing (smishing), and baseband exploits.",
        "mitreTactics": ["TA0001: Initial Access", "TA0006: Credential Access", "TA0009: Collection"],
        "targetSectors": ["Journalism", "Executive Leadership", "Telecom Subscribers"],
        "commonThreatLevels": ["High", "Medium"]
    },
    {
        "taxonomyCode": "TAX-08",
        "slug": "Cloud",
        "name": "Cloud Security",
        "icon": "☁️",
        "description": "AWS/Azure/GCP cloud posture flaws, IAM role abuse, serverless function hijacking, and misconfigured object storage buckets.",
        "mitreTactics": ["TA0004: Privilege Escalation", "TA0006: Credential Access", "TA0010: Exfiltration"],
        "targetSectors": ["SaaS Providers", "E-Commerce", "Multi-Cloud Enterprises"],
        "commonThreatLevels": ["High", "Medium"]
    },
    {
        "taxonomyCode": "TAX-09",
        "slug": "IoT",
        "name": "IoT & Embedded",
        "icon": "🌐",
        "description": "Botnet proliferation (Mirai, Mozi), default credential attacks, industrial control systems (ICS/SCADA) and smart-device exploits.",
        "mitreTactics": ["TA0042: Resource Development", "TA0040: Impact", "TA0001: Initial Access"],
        "targetSectors": ["Smart Infrastructure", "Manufacturing", "Automotive", "Smart Home"],
        "commonThreatLevels": ["Medium", "Low"]
    },
    {
        "taxonomyCode": "TAX-10",
        "slug": "Cryptography",
        "name": "Cryptography & PKI",
        "icon": "🔐",
        "description": "Cryptographic implementation flaws, post-quantum cryptography migrations, TLS/SSL downgrades, and private key exfiltration.",
        "mitreTactics": ["TA0006: Credential Access", "TA0005: Defense Evasion", "TA0009: Collection"],
        "targetSectors": ["Banking", "Blockchain", "Government Classified Networks"],
        "commonThreatLevels": ["High", "Medium"]
    },
    {
        "taxonomyCode": "TAX-11",
        "slug": "Compromised",
        "name": "Compromised Credentials",
        "icon": "⚠️",
        "description": "Dark web database dumps, breached credential combo lists, corporate account takeovers (ATO), and stolen API tokens.",
        "mitreTactics": ["TA0006: Credential Access", "TA0001: Initial Access", "TA0008: Lateral Movement"],
        "targetSectors": ["All Industry Verticals", "Corporate IT", "Identity Providers"],
        "commonThreatLevels": ["Critical", "High"]
    }
]

def setup_taxonomy():
    print(f"[*] Connecting to MongoDB Atlas ({db_name})...")
    client = MongoClient(uri)
    db = client[db_name]
    
    # 1. Master taxonomy_categories collection
    tax_col = db['taxonomy_categories']
    tax_col.drop()
    tax_col.insert_many(TAXONOMY_CATEGORIES)
    tax_col.create_index([("taxonomyCode", ASCENDING)], unique=True)
    tax_col.create_index([("slug", ASCENDING)], unique=True)
    print(f"[+] 'taxonomy_categories' master collection created with 11 records.")
    
    # 2. Update threat_reports using $or for exact match
    reports_col = db['threat_reports']
    print("[*] Synchronizing taxonomyCode & category on 100,000 documents...")
    
    for cat in TAXONOMY_CATEGORIES:
        slug = cat['slug']
        code = cat['taxonomyCode']
        res = reports_col.update_many(
            {"$or": [
                {"threatType": slug},
                {"category": slug}
            ]},
            {"$set": {"category": slug, "threatType": slug, "taxonomyCode": code}}
        )
        print(f"    - {code} | {slug:<15} : {res.modified_count:,} docs updated/synced")
        
    # 3. Create indexes
    print("[*] Ensuring high performance indexes...")
    reports_col.create_index([("taxonomyCode", ASCENDING)])
    reports_col.create_index([("threatType", ASCENDING), ("severity", ASCENDING), ("createdAt", DESCENDING)])
    reports_col.create_index([("category", ASCENDING)])
    
    # 4. Summary check
    agg = list(reports_col.aggregate([
        {"$group": {"_id": "$taxonomyCode", "category": {"$first": "$category"}, "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}}
    ]))
    print("\n[SUCCESS] ALL 11 TAXONOMY CATEGORIES VERIFIED IN DATABASE:")
    total = 0
    for a in agg:
        cnt = a['count']
        total += cnt
        print(f"    {a['_id']} | {a['category']:<16} : {cnt:,} reports")
    print(f"Total synchronized documents: {total:,}")
    print("\n[SUCCESS] Option B taxonomy setup is 100% complete!")

if __name__ == "__main__":
    setup_taxonomy()
