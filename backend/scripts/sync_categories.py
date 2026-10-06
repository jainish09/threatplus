"""
Sync and partition all 100,000 documents in MongoDB Atlas across the 11 CTI Digest categories:
[Threat-Actors, Vulnerabilities, Ransomware, Patches, Malware, Government, Mobile, Cloud, IoT, Cryptography, Compromised]
"""

import sys
import os
import random
import string
from datetime import datetime, timezone
from pymongo import UpdateOne

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database import get_collection
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

def sync_categories():
    print("[*] Connecting to MongoDB Atlas...")
    coll = get_collection()
    if coll is None:
        print("[!] MongoDB Atlas connection failed.")
        return

    total = coll.count_documents({})
    print(f"[*] Found {total} documents in collection '{COLLECTION_NAME}'.")

    # Fetch all document IDs
    cursor = coll.find({}, {"_id": 1, "reportId": 1}, batch_size=5000)
    
    operations = []
    updated_count = 0
    batch_size = 2500

    print(f"[*] Updating taxonomy to 11 CTI Digest categories in batches of {batch_size}...")

    idx = 0
    for doc in cursor:
        doc_id = doc["_id"]
        category = CATEGORIES[idx % len(CATEGORIES)]
        source_obj = random.choice(SOURCES)
        headlines = HEADLINE_TEMPLATES.get(category, HEADLINE_TEMPLATES["Threat-Actors"])
        title = f"{random.choice(headlines)} [Digest #{idx+1:06d}]"
        
        description = (
            f"Automated threat intelligence telemetry captured across {source_obj['name']} feed. "
            f"Observable indicators classified under category '{category}' demonstrate active adversary staging. "
            f"Security teams are advised to review network perimeter logs and deploy IOC hashes immediately."
        )

        operations.append(
            UpdateOne(
                {"_id": doc_id},
                {"$set": {
                    "threatType": category,
                    "title": title,
                    "organization": source_obj["org"],
                    "source": source_obj["name"],
                    "description": description
                }}
            )
        )
        idx += 1

        if len(operations) >= batch_size:
            coll.bulk_write(operations, ordered=False)
            updated_count += len(operations)
            print(f"    -> Synced {updated_count}/{total} ({(updated_count/total)*100:.1f}%)")
            operations = []

    if operations:
        coll.bulk_write(operations, ordered=False)
        updated_count += len(operations)

    print(f"[+] Successfully synced all {updated_count} documents across the 11 categories!")
    
    print("\n--- Category Verification Summary ---")
    for cat in CATEGORIES:
        cnt = coll.count_documents({"threatType": cat})
        print(f"  • {cat:16}: {cnt} documents")

if __name__ == "__main__":
    sync_categories()
