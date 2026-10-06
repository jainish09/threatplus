import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv('backend/.env')
uri = os.getenv('MONGODB_URI') or os.getenv('MONGO_URI')
client = MongoClient(uri)
db = client['threat_intel_db']
col = db['threat_reports']

print("Distinct threatType:", col.distinct("threatType"))
print("Distinct category:", col.distinct("category"))

# Check a document without taxonomyCode
missing = col.find_one({"taxonomyCode": {"$exists": False}})
print("Sample document without taxonomyCode:", missing)
