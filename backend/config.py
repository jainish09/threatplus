import os
from dotenv import load_dotenv

# Robustly load .env from backend directory or workspace root
env_path = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(env_path):
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "threat_intel_db")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "threat_reports")
PORT = int(os.getenv("PORT", 8080))
HOST = os.getenv("HOST", "127.0.0.1")

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "3811fd5f4aee0a87cb89bf0dc416cbdbbee60bed61214850957d012edd11eac9")
MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY", "0c09fd8fefb007cb426880c243a40f85b731bf756533ed8e")

