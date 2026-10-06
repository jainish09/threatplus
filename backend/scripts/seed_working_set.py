"""
MongoDB Lab 7.2 - OpenSource CTI Digest Working Set Seeding Script
Populates MongoDB Atlas with 100,000 cybersecurity threat intelligence documents (~2 KB each).
Categorized exactly according to CTI Digest taxonomy:
[Threat-Actors, Vulnerabilities, Ransomware, Patches, Malware, Government, Mobile, Cloud, IoT, Cryptography, Compromised]
"""

import sys
import os
import random
import string
from datetime import datetime, timezone

# Add parent directory to path to import config & database
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database import get_database, get_collection
from config import COLLECTION_NAME

CATEGORIES = [
    "Threat-Actors",
    "Vulnerabilities",
    "Ransomware",
    "Patches",
    "Malware",
    "Government",
    "Mobile",
    "Cloud",
    "IoT",
    "Cryptography",
    "Compromised"
]

SOURCES = [
    {"name": "The Hacker News", "org": "The Hacker News Media Group"},
    {"name": "Dark Reading", "org": "Dark Reading Enterprise Security"},
    {"name": "Infosecurity Magazine", "org": "Infosecurity Intelligence Group"},
    {"name": "The Record", "org": "The Record by Recorded Future"},
    {"name": "Schneier on Security", "org": "Schneier Cryptography & Security"},
    {"name": "BleepingComputer", "org": "BleepingComputer Threat Research"},
    {"name": "CISA Advisory", "org": "Cybersecurity & Infrastructure Security Agency (CISA)"}
]

SEVERITIES = ["Critical", "High", "Medium", "Low"]

HEADLINE_TEMPLATES = {
    "Threat-Actors": [
        "Antino Backdoor Uses Outlook and OneDrive for C2 in China-Nexus Espionage Campaign",
        "Microsoft: AI Cuts Post-Compromise Attack Time to Minutes",
        "Volt Typhoon Pre-Positions on Critical Infrastructure Networks Across North America",
        "Scattered Spider Targets Identity Providers via Automated SIM Swapping Pipelines",
        "Russian APT29 Actors Leverage Stealthy GraphAPI Backdoors for Cloud Ingress",
        "Lazarus Group Targets Cryptocurrency Exchanges with Malicious NPM Packages"
    ],
    "Vulnerabilities": [
        "Dell CSM Flaws Enable Unauthenticated Admin Access and Root on Kubernetes Nodes",
        "Kiteworks & Citrix Incidents Show Challenges of Zero-Day Vulnerability Response",
        "Critical Remote Code Execution Disclosed in Edge Gateway & VPN Appliances",
        "Apache ActiveMQ Remote Code Execution Flaw Actively Exploited by Ransomware",
        "Ivanti Connect Secure Zero-Days Exploited for Lateral Network Traversal",
        "Linux Kernel Privilege Escalation Vulnerability Patched Across Enterprise Distros"
    ],
    "Ransomware": [
        "Mississippi Mayor Says Ransomware Incident Led City to Shut Down Systems",
        "'Warlock' Ransomware Used in Attacks on Critical Infrastructure in Portuguese and Spanish Regions",
        "LockBit 3.0 Variant Deploys Bring-Your-Own-Vulnerable-Driver (BYOVD) for Defense Evasion",
        "BlackCat/ALPHV Syndicate Claims Exfiltration of 6 TB of Healthcare Telemetry",
        "Akira Ransomware Targets Cisco SSL VPNs Lacking Multi-Factor Authentication",
        "Multi-Extortion Ransomware Gangs Transition to Data-Exfiltration-Only Extortion"
    ],
    "Patches": [
        "Microsoft Patch Tuesday Addresses 84 Security Flaws, Including 2 Active Zero-Days",
        "Apple Releases Emergency Security Updates for iOS and macOS Zero-Click Exploitation",
        "Google Chrome Zero-Day Patch Rolled Out Following In-The-Wild Exploit Telemetry",
        "Cisco Issues Urgent Patches for Critical Command Injection in IOS XE Software",
        "Adobe Emergency Bulletin Addresses Memory Corruption Flaw in Document Services"
    ],
    "Malware": [
        "[Virtual Event] Building a Secure AI Strategy for the Enterprise",
        "QakBot Revival: New Encrypted Loader Drops Modular Stealer Payloads",
        "Lumma Stealer Distributed via Malicious YouTube Video Game Patch Descriptions",
        "AsyncRAT Infiltrates Financial Institutions via Weaponized Excel Macro Attachments",
        "Stealthy Hypervisor Rootkit Evades Kernel Telemetry Across VMware ESXi Hosts"
    ],
    "Government": [
        "Federal Agencies Mandated to Implement FIPS Quantum-Resistant Cryptography Standards",
        "NSA & CISA Issue Joint Cybersecurity Advisory on Hardening Border Gateway Protocol",
        "State-Sponsored Cyber Espionage Targeting Defense Industrial Base Contractors",
        "EU Cybersecurity Agency (ENISA) Mandates Strict Incident Reporting Timelines",
        "White House Releases National Cybersecurity Strategy Implementation Plan"
    ],
    "Mobile": [
        "Zero-Click Pegasus Spyware Delivered via iMessage WebP Image Parsing Flaw",
        "Malicious Android Banking Trojan 'Anatsa' Bypasses Google Play Verification",
        "SIM Swapping Syndicate Indicted for Hijacking High-Profile Executive Cloud Accounts",
        "Fake Signal and Telegram Apps in Android App Stores Deliver Backdoor Payloads"
    ],
    "Cloud": [
        "[Virtual Event] What Every Enterprise Should Know About Securing Cloud Assets in the Age of AI",
        "Misconfigured AWS S3 and GCP Storage Buckets Expose IAM Service Account Keys",
        "Kubernetes API Server Exploitation via Unauthenticated RBAC Privilege Escalation",
        "Azure Active Directory Federated Token Abuse Enables Lateral Cloud Tenant Movement"
    ],
    "IoT": [
        "Friday Squid Blogging: EU is Trying to Fight Unregulated Squid Fishing",
        "The EDR Blind Spot: 3 Ways Browser & IoT Edge Attacks Evade Endpoint Detection",
        "Mirai Botnet Fork Targets Unpatched Smart Grid Meters and Industrial Sensors",
        "Firmware Implant Discovered on Enterprise Routers Survives Factory Resets"
    ],
    "Cryptography": [
        "Post-Quantum Cryptography Migration: Transitioning from RSA-2048 to ML-KEM Algorithms",
        "Store Now, Decrypt Later (SNDL) Threat Horizon Analyzed for Encrypted Telemetry",
        "Weak Elliptic Curve Implementation in Legacy TLS Stack Enables Session Replay Attacks"
    ],
    "Compromised": [
        "Okta Customer Support Management System Breach Exposes Enterprise Session Tokens",
        "XZ Utils Backdoor Infiltration Highlights Open Source Supply Chain Fragility",
        "SolarWinds Style Build System Code Injection Discovered in Enterprise CI/CD Pipeline"
    ]
}

def generate_payload_padding(target_bytes=1400):
    """Generates synthetic payload to achieve exact ~2.0 - 2.3 KB per BSON document."""
    chars = string.ascii_letters + string.digits + " ,.-;:#/@"
    return "".join(random.choices(chars, k=target_bytes))

def create_sample_document(index: int):
    category = random.choice(CATEGORIES)
    source_obj = random.choice(SOURCES)
    headlines = HEADLINE_TEMPLATES.get(category, HEADLINE_TEMPLATES["Threat-Actors"])
    base_title = random.choice(headlines)
    title = f"{base_title} [Digest #{index:06d}]"
    
    year = random.choices([2026, 2025, 2024, 2023], weights=[0.4, 0.35, 0.15, 0.1])[0]
    severity = random.choices(SEVERITIES, weights=[0.25, 0.45, 0.20, 0.10])[0]
    
    report_id = f"CTI-{year}-{index:06d}"
    
    description = (
        f"Automated threat intelligence telemetry captured across {source_obj['name']} feed. "
        f"Observable indicators classified under category '{category}' demonstrate active adversary staging. "
        f"Security teams are advised to review network perimeter logs and deploy IOC hashes immediately."
    )

    # BSON Payload (~2 KB total document size for Working Set analysis)
    payload = {
        "raw_indicators": [
            f"198.51.100.{random.randint(1, 254)}",
            f"203.0.113.{random.randint(1, 254)}",
            f"192.0.2.{random.randint(1, 254)}"
        ],
        "hashes": {
            "sha256": "".join(random.choices(string.hexdigits.lower(), k=64)),
            "md5": "".join(random.choices(string.hexdigits.lower(), k=32))
        },
        "mitre_tactics": ["Initial Access (T1190)", "Execution (T1059)", "Persistence (T1505)"],
        "cve_list": [f"CVE-{year}-{random.randint(1000, 9999)}"],
        "payload_buffer": generate_payload_padding(1400)
    }

    return {
        "reportId": report_id,
        "title": title,
        "organization": source_obj["org"],
        "year": year,
        "threatType": category,  # Exact CTI Digest Category
        "severity": severity,
        "description": description,
        "source": source_obj["name"],
        "data": payload,
        "createdAt": datetime.now(timezone.utc).isoformat()
    }

def seed_database(target_count=100000, batch_size=2500):
    print(f"[*] Connecting to MongoDB Atlas...")
    coll = get_collection()
    if coll is None:
        print("[!] Failed to connect to MongoDB Atlas. Check backend/.env")
        return

    current_count = coll.count_documents({})
    print(f"[*] Current document count in '{COLLECTION_NAME}': {current_count}")

    # Re-indexing and seeding
    print(f"[*] Creating optimized indexes for CTI Digest taxonomy...")
    coll.create_index("reportId", unique=True)
    coll.create_index("threatType")
    coll.create_index("year")
    coll.create_index("severity")
    coll.create_index("source")
    coll.create_index("createdAt")

    needed = target_count - current_count
    if needed <= 0:
        print(f"[*] Collection already contains {current_count} documents. Updating existing records with CTI categories...")
        # Update existing records to ensure categories match CTI Digest taxonomy
        for cat in CATEGORIES:
            headlines = HEADLINE_TEMPLATES.get(cat, [])
            coll.update_many(
                {"threatType": {"$regex": cat.split("-")[0], "$options": "i"}},
                {"$set": {"threatType": cat}}
            )
        print(f"[+] Taxonomy updated for all documents in '{COLLECTION_NAME}'!")
        return

    print(f"[*] Generating and inserting {needed} documents with CTI Digest taxonomy in batches of {batch_size}...")

    batch = []
    inserted = 0
    for i in range(current_count + 1, target_count + 1):
        batch.append(create_sample_document(i))
        if len(batch) >= batch_size:
            coll.insert_many(batch, ordered=False)
            inserted += len(batch)
            print(f"    -> Inserted {inserted}/{needed} ({(inserted/needed)*100:.1f}%)")
            batch = []

    if batch:
        coll.insert_many(batch, ordered=False)
        inserted += len(batch)

    print(f"[+] Seeding complete! Total documents in '{COLLECTION_NAME}': {coll.count_documents({})}")

if __name__ == "__main__":
    count = 100000
    if len(sys.argv) > 1:
        try:
            count = int(sys.argv[1])
        except ValueError:
            pass
    seed_database(count)
